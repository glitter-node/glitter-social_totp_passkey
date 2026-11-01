<?php

namespace Glitter\SocialTOTPPasskey\Listeners;

use App\Contracts\Extension\HookListenerInterface;
use Illuminate\Support\Facades\Log;
use Glitter\SocialTOTPPasskey\Services\SocialAuthService;
use Glitter\SocialTOTPPasskey\Support\BrandIcons;
use Glitter\SocialTOTPPasskey\Support\SocialLoginRateLimiters;

/**
 * 인증 화면(`auth/login`, `auth/register`)에 소셜 로그인 버튼을
 * `core.layout_extension.after_apply` 필터로 주입한다. 로그인 화면에는
 * extension_point 가 없어(조사 결과) 코어/템플릿 파일을 건드리지 않는 이 방식이
 * 유일한 무변경 주입 경로다 (g7-forum-addon 의 board/show 위젯 주입과 동일 패턴).
 *
 * 버튼은 `_global.plugins['glitter-social_totp_passkey'].{provider}_enabled` 로 켜져 있을
 * 때만 보인다(플러그인 설정의 frontend_schema 노출값, 별도 API 호출 불필요).
 */
class LoginPageWidgetListener implements HookListenerInterface
{
    public function __construct(private readonly SocialAuthService $socialAuth) {}

    private const WIDGET_ID = 'glitter_social_totp_passkey_widget';

    private const API_PREFIX = '/api/plugins/glitter-social_totp_passkey';

    private const INIT_ACTION_MARKER = 'glitter_social_totp_passkey_exchange';

    /** 로그인 카드의 의미적 자식 구조를 확인하기 위한 컴포넌트 이름 */
    private const LOGIN_HEADING_NAME = 'h2';

    private const LOGIN_FORM_NAME = 'form';

    private const REGISTER_FORM_PARTIAL = 'partials/auth/_register_form.json';

    /** 로그인 카드 안에서 일반 로그인 Form과 하단 링크 영역을 식별한다. */
    private const BOTTOM_LINKS_CLASSNAME = 'mt-4 flex items-center justify-between text-sm';

    public static function getSubscribedHooks(): array
    {
        return [
            'core.layout_extension.after_apply' => [
                'method' => 'injectWidget',
                'type' => 'filter',
                'priority' => 20,
            ],
        ];
    }

    public function handle(...$args): void {}

    public function injectWidget(array $layout, int $templateId = 0): array
    {
        $layoutName = $layout['layout_name'] ?? null;

        if (! in_array($layoutName, ['auth/login', 'auth/register'], true)) {
            return $layout;
        }

        if (! isset($layout['components']) || ! is_array($layout['components'])) {
            return $layout;
        }

        if (! $this->treeHasNodeId($layout['components'], self::WIDGET_ID)) {
            $injected = 0;
            $layout['components'] = $layoutName === 'auth/register'
                ? $this->spliceIntoRegisterFormContainer($layout['components'], $injected)
                : $this->spliceIntoLoginFormContainer($layout['components'], $injected);

            if ($injected === 0) {
                Log::channel('glitter_social_totp_passkey')->error('[glitter-social_totp_passkey] 인증 폼 구조 앵커를 찾지 못해 소셜 로그인 버튼을 주입하지 못했습니다.', [
                    'template_id' => $templateId,
                    'layout_name' => $layoutName,
                ]);
            }
        }

        // OAuth callback은 일반 로그인에서는 exchange로, 2FA 대상 계정에서는
        // pending context로 /login에 돌아온다. 두 흐름 모두 login 화면이 소비한다.
        if ($layoutName === 'auth/login') {
            $initActions = $this->ensureExchangeInitAction($layout['initActions'] ?? []);
            $layout['initActions'] = $this->ensureSocialTotpTransitionInitAction($this->ensureSocialTotpSetupInitAction($initActions));
        } elseif ($layoutName === 'auth/register') {
            $layout['initActions'] = $this->ensureSocialRegistrationTotpInitAction($layout['initActions'] ?? []);
        }

        return $layout;
    }

    /**
     * @param  array<int, array>  $nodes
     */
    private function spliceIntoLoginFormContainer(array $nodes, int &$injected): array
    {
        foreach ($nodes as &$node) {
            if (! is_array($node)) {
                continue;
            }

            if ($this->isLoginFormContainer($node)) {
                $node['children'] = $this->insertAroundLoginForm($node['children'], $injected);

                if ($injected > 0) {
                    continue;
                }
            }

            if (isset($node['children']) && is_array($node['children'])) {
                $node['children'] = $this->spliceIntoLoginFormContainer($node['children'], $injected);
            }
        }

        return $nodes;
    }

    /**
     * 제목 다음에는 현재 소셜 회원가입 단계 패널을, 그 뒤에는 소셜 위젯과
     * 일반 회원가입 폼을 주입한다.
     *
     * @param  array<int, array>  $nodes
     */
    private function spliceIntoRegisterFormContainer(array $nodes, int &$injected): array
    {
        foreach ($nodes as &$node) {
            if (! is_array($node)) {
                continue;
            }

            if ($this->isRegisterFormContainer($node)) {
                $node['children'] = $this->insertAroundRegisterForm($node['children'], $injected);

                if ($injected > 0) {
                    continue;
                }
            }

            if (isset($node['children']) && is_array($node['children'])) {
                $node['children'] = $this->spliceIntoRegisterFormContainer($node['children'], $injected);
            }
        }

        return $nodes;
    }

    /**
     * Identify the login card from its semantic child structure, not visual styling.
     *
     * The final layout-extension payload is a flattened component tree. The login
     * card is the direct parent of the login heading, login form, and the existing
     * bottom-links row. Requiring all three direct children prevents an unrelated
     * container with a similarly styled link row from becoming an injection target.
     *
     * @param  array<string, mixed>  $node
     */
    private function isLoginFormContainer(array $node): bool
    {
        if (! isset($node['children']) || ! is_array($node['children'])) {
            return false;
        }

        $hasLoginHeading = false;
        $hasLoginForm = false;
        $hasBottomLinks = false;

        foreach ($node['children'] as $child) {
            if (! is_array($child)) {
                continue;
            }

            $name = strtolower((string) ($child['name'] ?? ''));

            if (in_array($name, ['h1', self::LOGIN_HEADING_NAME], true)) {
                $hasLoginHeading = true;
            }

            if ($name === self::LOGIN_FORM_NAME) {
                $hasLoginForm = true;
            }

            if (($child['props']['className'] ?? null) === self::BOTTOM_LINKS_CLASSNAME
                || $this->isLoginSwitch($child)
            ) {
                $hasBottomLinks = true;
            }
        }

        return $hasLoginHeading && $hasLoginForm && $hasBottomLinks;
    }

    /**
     * Identify the register container from semantic registration content.
     *
     * The current project-hub layout has a register heading, a form, and a
     * "already a member" switch. The directory template uses the equivalent
     * register heading, form, and register-to-login link. Translation keys
     * and the /login destination make this narrower than a generic heading
     * plus form container while remaining independent of presentation CSS.
     *
     * @param  array<string, mixed>  $node
     */
    private function isRegisterFormContainer(array $node): bool
    {
        if (! isset($node['children']) || ! is_array($node['children'])) {
            return false;
        }

        $hasRegisterHeading = false;
        $hasRegisterForm = false;
        $hasRegisterSwitch = false;

        foreach ($node['children'] as $child) {
            if (! is_array($child)) {
                continue;
            }

            $name = strtolower((string) ($child['name'] ?? ''));

            if (in_array($name, ['h1', 'h2'], true)
                && in_array($child['text'] ?? null, ['$t:auth.register.title', '$t:auth_page.register_heading'], true)
            ) {
                $hasRegisterHeading = true;
            }

            if ($this->isRegisterFormNode($child)) {
                $hasRegisterForm = true;
            }

            if ($this->isRegisterSwitch($child)) {
                $hasRegisterSwitch = true;
            }
        }

        return $hasRegisterHeading && $hasRegisterForm && $hasRegisterSwitch;
    }

    /**
     * Recognize both direct Form nodes and the project-hub register partial.
     *
     * The exact partial path is a semantic layout contract; broad partial or
     * CSS matching would allow unrelated containers to become injection targets.
     *
     * @param  array<string, mixed>  $node
     */
    private function isRegisterFormNode(array $node): bool
    {
        $name = strtolower((string) ($node['name'] ?? ''));

        return $name === self::LOGIN_FORM_NAME
            || ($node['partial'] ?? null) === self::REGISTER_FORM_PARTIAL;
    }

    /**
     * Detect the semantic register-to-login switch without matching its CSS.
     *
     * @param  array<string, mixed>  $node
     */
    private function isRegisterSwitch(array $node): bool
    {
        if (! isset($node['children']) || ! is_array($node['children'])) {
            return false;
        }

        $hasPrompt = false;
        $hasLoginDestination = false;

        foreach ($node['children'] as $child) {
            if (! is_array($child)) {
                continue;
            }

            if (in_array($child['text'] ?? null, ['$t:auth.already_member', '$t:auth_page.register_login_prompt'], true)) {
                $hasPrompt = true;
            }

            $name = strtolower((string) ($child['name'] ?? ''));
            $href = $child['props']['href'] ?? null;
            $actions = $child['actions'] ?? [];

            if ($name === 'a' && $href === '/login') {
                $hasLoginDestination = true;
            }

            foreach (is_array($actions) ? $actions : [] as $action) {
                if (($action['type'] ?? null) === 'click'
                    && ($action['handler'] ?? null) === 'navigate'
                    && ($action['params']['path'] ?? null) === '/login'
                ) {
                    $hasLoginDestination = true;
                }
            }
        }

        return $hasPrompt && $hasLoginDestination;
    }

    /**
     * Place the social-login TOTP panel first, followed by the provider widget
     * and regular login Form. Other account-management panels retain their
     * existing position before the bottom links.
     *
     * @param array<int, array> $children
     */
    private function insertAroundLoginForm(array $children, int &$injected): array
    {
        $formIndex = null;
        $anchorIndex = null;

        foreach ($children as $index => $child) {
            if (! is_array($child)) {
                continue;
            }

            if ($formIndex === null && strtolower((string) ($child['name'] ?? '')) === self::LOGIN_FORM_NAME) {
                $formIndex = $index;
            }

            if (($child['props']['className'] ?? null) === self::BOTTOM_LINKS_CLASSNAME
                || $this->isLoginSwitch($child)
            ) {
                $anchorIndex = $index;
                break;
            }
        }

        if ($formIndex === null || $anchorIndex === null || $formIndex >= $anchorIndex) {
            return $children;
        }

        array_splice($children, $formIndex, 0, [
            $this->buildTwoFactorNode(),
            $this->buildPasskeyTotpNode(),
            $this->buildPasskeyPasswordChangeNode(),
            $this->buildWidgetNode('login'),
        ]);

        // The first insertion shifts the existing bottom-link anchor by four nodes.
        $anchorIndex += 4;
        array_splice($children, $anchorIndex, 0, [
            $this->buildSocialTotpEnrollmentNode(),
            $this->buildSocialTotpSetupNode(),
            $this->buildSocialTotpTransitionSetupNode(),
        ]);
        $injected++;

        return $children;
    }

    /**
     * Known alternate-template login switch: a paragraph containing a
     * registration link. Unknown containers are intentionally not matched.
     *
     * @param  array<string, mixed>  $node
     */
    private function isLoginSwitch(array $node): bool
    {
        if (($node['props']['className'] ?? null) !== 'gd-auth-switch'
            || ! isset($node['children'])
            || ! is_array($node['children'])
        ) {
            return false;
        }

        foreach ($node['children'] as $child) {
            if (! is_array($child)) {
                continue;
            }

            if (($child['props']['href'] ?? null) === '/register') {
                return true;
            }

            foreach (is_array($child['actions'] ?? null) ? $child['actions'] : [] as $action) {
                if (($action['type'] ?? null) === 'click'
                    && ($action['handler'] ?? null) === 'navigate'
                    && ($action['params']['path'] ?? null) === '/register'
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Place all query-gated social registration steps immediately before the
     * social-provider widget and regular registration form. Their mutually
     * exclusive conditions keep the current step at the same top position
     * across full-page redirects and the TOTP enrollment state update.
     *
     * @param array<int, array> $children
     */
    private function insertAroundRegisterForm(array $children, int &$injected): array
    {
        $formIndex = null;
        $switchIndex = null;

        foreach ($children as $index => $child) {
            if (! is_array($child)) {
                continue;
            }

            if ($formIndex === null && $this->isRegisterFormNode($child)) {
                $formIndex = $index;
            }

            if ($this->isRegisterSwitch($child)) {
                $switchIndex = $index;
                break;
            }
        }

        if ($formIndex === null || $switchIndex === null || $formIndex >= $switchIndex) {
            return $children;
        }

        array_splice($children, $formIndex, 0, [
            $this->buildRegistrationNode(),
            $this->buildRegistrationIdentityNode(),
            $this->buildRegistrationTotpNode(),
            $this->buildWidgetNode('register'),
        ]);
        $injected++;

        return $children;
    }

    private function buildWidgetNode(string $context): array
    {
        $translationGroup = $context === 'register' ? 'register' : 'login';
        $providerVisibility = "_global.plugins?.['glitter-social_totp_passkey']?.naver_enabled || _global.plugins?.['glitter-social_totp_passkey']?.kakao_enabled || _global.plugins?.['glitter-social_totp_passkey']?.google_enabled || _global.plugins?.['glitter-social_totp_passkey']?.facebook_enabled || _global.plugins?.['glitter-social_totp_passkey']?.github_enabled";
        $widgetVisibility = $context === 'login'
            ? "{{!_global.twoFactor?.required && (({$providerVisibility}) || (_global.plugins?.['glitter-social_totp_passkey']?.passkey_enabled && _global.plugins?.['glitter-social_totp_passkey']?.passkey_login_enabled))}}"
            : "{{{$providerVisibility}}}";

        $widget = [
            'id' => self::WIDGET_ID,
            'comment' => 'glitter-social_totp_passkey: 소셜 로그인 버튼',
            'type' => 'basic',
            'name' => 'Div',
            'if' => $widgetVisibility,
            'props' => ['className' => 'mt-6 space-y-3'],
            'children' => [
                [
                    'type' => 'basic',
                    'name' => 'Div',
                    'props' => ['className' => 'relative my-4'],
                    'children' => [
                        [
                            'type' => 'basic', 'name' => 'Div',
                            'props' => ['className' => 'absolute inset-0 flex items-center'],
                            'children' => [[
                                'type' => 'basic', 'name' => 'Div',
                                'props' => ['className' => 'w-full border-t border-gray-200 dark:border-gray-700'],
                            ]],
                        ],
                        [
                            'type' => 'basic', 'name' => 'Div',
                            'props' => ['className' => 'relative flex justify-center'],
                            'children' => [[
                                'type' => 'basic', 'name' => 'Span',
                                'props' => ['className' => 'px-3 bg-white dark:bg-gray-800 text-sm text-gray-500 dark:text-gray-400'],
                                'text' => '$t:glitter-social_totp_passkey.login.divider',
                            ]],
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'A',
                    'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.naver_enabled}}",
                    'props' => [
                        'href' => '/api/plugins/glitter-social_totp_passkey/naver/redirect',
                        'className' => 'w-full flex items-center justify-center gap-2 py-3 rounded-lg font-medium border border-[#03C75A] bg-[#03C75A] text-white hover:bg-[#02B350] transition-colors',
                    ],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Img',
                            'props' => [
                                'src' => BrandIcons::naverDataUri(),
                                'alt' => '',
                                'className' => 'w-5 h-5',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Span',
                            'text' => "\$t:glitter-social_totp_passkey.{$translationGroup}.naver_button",
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'A',
                    'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.kakao_enabled}}",
                    'props' => [
                        // 고정 경로 — g7 표현식 평가기(SafeExpressionEvaluator)는 encodeURIComponent 등
                        // 화이트리스트 밖 전역 함수를 호출하지 못하고, 실패 시 {{ }} 원문을 그대로 흘린다.
                        'href' => '/api/plugins/glitter-social_totp_passkey/kakao/redirect',
                        'className' => 'w-full flex items-center justify-center gap-2 py-3 rounded-lg font-medium bg-[#FEE500] text-black/85 hover:opacity-90 transition-opacity',
                    ],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Img',
                            'props' => [
                                'src' => BrandIcons::kakaoDataUri(),
                                'alt' => '',
                                'className' => 'w-5 h-5',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Span',
                            'text' => "\$t:glitter-social_totp_passkey.{$translationGroup}.kakao_button",
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'A',
                    'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.google_enabled}}",
                    'props' => [
                        'href' => '/api/plugins/glitter-social_totp_passkey/google/redirect',
                        'className' => 'w-full flex items-center justify-center gap-2 py-3 rounded-lg font-medium border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors',
                    ],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Img',
                            'props' => [
                                'src' => BrandIcons::googleDataUri(),
                                'alt' => '',
                                'className' => 'w-5 h-5',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Span',
                            'text' => "\$t:glitter-social_totp_passkey.{$translationGroup}.google_button",
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'A',
                    'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.facebook_enabled}}",
                    'props' => [
                        'href' => '/api/plugins/glitter-social_totp_passkey/facebook/redirect',
                        'className' => 'w-full flex items-center justify-center gap-2 py-3 rounded-lg font-medium border border-[#1877F2] bg-[#1877F2] text-white hover:bg-[#166FE5] transition-colors',
                    ],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Img',
                            'props' => [
                                'src' => BrandIcons::facebookDataUri(),
                                'alt' => '',
                                'className' => 'w-5 h-5',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Span',
                            'text' => "\$t:glitter-social_totp_passkey.{$translationGroup}.facebook_button",
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'A',
                    'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.github_enabled}}",
                    'props' => [
                        'href' => '/api/plugins/glitter-social_totp_passkey/github/redirect',
                        'className' => 'w-full flex items-center justify-center gap-2 py-3 rounded-lg font-medium border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors',
                    ],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Img',
                            'props' => [
                                'src' => BrandIcons::githubDataUri(),
                                'alt' => '',
                                'className' => 'w-5 h-5',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Span',
                            'text' => "\$t:glitter-social_totp_passkey.{$translationGroup}.github_button",
                        ],
                    ],
                ],
            ],
        ];

        $providerNodes = array_slice($widget['children'], 1);
        $providerNodesByProvider = array_combine(SocialAuthService::PROVIDERS, $providerNodes);
        $orderedProviders = $this->socialAuth->orderedProviders();
        $orderedProviderNodes = array_values(array_map(
            static fn (string $provider): array => $providerNodesByProvider[$provider],
            $orderedProviders,
        ));
        $divider = $widget['children'][0];
        $widget['children'] = [...$orderedProviderNodes, $divider];

        if ($context === 'login') {
            array_unshift($widget['children'], [
                'id' => 'glitter_social_totp_passkey_login_button',
                'type' => 'basic',
                'name' => 'Button',
                'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.passkey_enabled && _global.plugins?.['glitter-social_totp_passkey']?.passkey_login_enabled}}",
                'props' => [
                    'type' => 'button',
                    'className' => 'w-full rounded-lg border border-gray-300 px-4 py-3 font-medium text-gray-800 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-100 dark:hover:bg-gray-700',
                ],
                'text' => '$t:glitter-social_totp_passkey.login.passkey_button',
                'actions' => [[
                    'type' => 'click',
                    'handler' => 'glitter-social_totp_passkey.passkeyLogin',
                    'params' => ['purpose' => 'login'],
                ]],
            ]);
        }

        return $widget;
    }

    /**
     * OAuth callback이 2FA pending context로 돌아온 경우에만 보이는 최소 입력 UI.
     * challenge 자체는 서버에 보관하고, 브라우저에는 opaque pending id만 둔다.
     */
    private function buildTwoFactorNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_two_factor',
            'if' => '{{query?.glitter_social_totp_passkey_two_factor}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30'],
            'children' => [
                [
                    'type' => 'basic',
                    'name' => 'H3',
                    'props' => ['className' => 'mb-2 text-base font-semibold text-gray-900 dark:text-gray-100'],
                    'text' => '$t:glitter-social_totp_passkey.login.two_factor_title',
                ],
                [
                    'type' => 'basic',
                    'name' => 'P',
                    'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'],
                    'text' => '$t:glitter-social_totp_passkey.login.two_factor_description',
                ],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'dataKey' => 'socialTwoFactor',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'target' => '/api/plugins/glitter-social_totp_passkey/two-factor',
                        'params' => [
                            'method' => 'POST',
                            'body' => [
                                'pending_id' => '{{query.glitter_social_totp_passkey_two_factor}}',
                                'code' => '{{$event.target.code.value}}',
                            ],
                        ],
                        'onSuccess' => [[
                            'handler' => 'openWindow',
                            'target' => '{{response.redirect_url}}',
                            'params' => ['target' => '_self'],
                        ]],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => [
                                'type' => 'error',
                                'message' => '$t:glitter-social_totp_passkey.login.two_factor_failed',
                            ],
                        ]],
                    ]],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Label',
                            'props' => ['className' => 'sr-only', 'htmlFor' => 'glitter_social_totp_passkey-two-factor-code'],
                            'text' => '$t:glitter-social_totp_passkey.login.two_factor_code',
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Input',
                            'props' => [
                                'id' => 'glitter_social_totp_passkey-two-factor-code',
                                'name' => 'code',
                                'type' => 'text',
                                'inputMode' => 'numeric',
                                'autoComplete' => 'one-time-code',
                                'required' => true,
                                'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800',
                                'placeholder' => '$t:glitter-social_totp_passkey.login.two_factor_code_placeholder',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Button',
                            'props' => [
                                'type' => 'submit',
                                'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900',
                            ],
                            'text' => '$t:glitter-social_totp_passkey.login.two_factor_submit',
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'Button',
                    'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.passkey_enabled && _global.plugins?.['glitter-social_totp_passkey']?.passkey_totp_substitution_enabled}}",
                    'props' => ['type' => 'button', 'className' => 'mt-3 w-full rounded-md border border-gray-300 px-4 py-2 font-medium dark:border-gray-600'],
                    'text' => '$t:glitter-social_totp_passkey.login.passkey_substitute_button',
                    'actions' => [[
                        'type' => 'click',
                        'handler' => 'glitter-social_totp_passkey.passkeySocial',
                        'params' => [
                            'purpose' => 'social',
                            'pendingId' => '{{query.glitter_social_totp_passkey_two_factor}}',
                        ],
                    ]],
                ],
            ],
        ];
    }

    private function buildPasskeyTotpNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_login_totp',
            'if' => '{{!!_global.glitterPasskeyTotpPending}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.login.passkey_totp_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm'], 'text' => '$t:glitter-social_totp_passkey.login.passkey_totp_description'],
                [
                    'type' => 'basic', 'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'glitter-social_totp_passkey.passkeyLoginTotp',
                        'params' => [
                            'pendingId' => '{{_global.glitterPasskeyTotpPending}}',
                            'expiresAt' => '{{_global.glitterPasskeyTotpExpiresAt}}',
                            'code' => '{{$event.target.code.value}}',
                        ],
                        'onError' => [
                            ['handler' => 'toast', 'if' => "{{['passkey_login_expired', 'passkey_login_stale'].includes(error.error_code)}}", 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.passkey_login_restart']],
                            ['handler' => 'toast', 'if' => "{{!['passkey_login_expired', 'passkey_login_stale'].includes(error.error_code)}}", 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.passkey_failed']],
                        ],
                    ]],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'code', 'type' => 'text', 'inputMode' => 'numeric', 'required' => true, 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800']],
                        ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'disabled' => '{{_global.glitterPasskeyTotpSubmitting}}', 'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 text-white disabled:opacity-50 dark:bg-gray-100 dark:text-gray-900'], 'text' => '$t:glitter-social_totp_passkey.login.two_factor_submit'],
                    ],
                ],
            ],
        ];
    }

    private function buildPasskeyPasswordChangeNode(): array
    {
        $clearState = [
            'target' => 'global',
            'glitterPasskeyPasswordChange' => null,
            'glitterPasskeyPasswordChangeSubmitting' => false,
            'glitterPasskeyTotpPending' => null,
            'glitterPasskeyTotpExpiresAt' => null,
        ];

        $challengeFailure = [
            ['handler' => 'setState', 'params' => ['target' => 'global', 'glitterPasskeyPasswordChangeSubmitting' => false]],
            ['handler' => 'setState', 'if' => '{{error.errors?.challenge_id}}', 'params' => $clearState],
            ['handler' => 'toast', 'if' => '{{error.errors?.challenge_id}}', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.passkey_password_change_restart']],
            ['handler' => 'toast', 'if' => '{{!error.errors?.challenge_id}}', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.passkey_password_change_failed']],
        ];

        return [
            'id' => 'glitter_social_totp_passkey_password_change',
            'if' => '{{!!_global.glitterPasskeyPasswordChange?.required}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.login.passkey_password_change_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm'], 'text' => '$t:glitter-social_totp_passkey.login.passkey_password_change_description'],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'actions' => [
                        [
                            'type' => 'submit',
                            'handler' => 'setState',
                            'params' => ['target' => 'global', 'glitterPasskeyPasswordChangeSubmitting' => true],
                        ],
                        [
                            'type' => 'submit',
                            'handler' => 'loginPasswordChange',
                            'target' => 'user',
                            'params' => ['body' => [
                                'challenge_id' => '{{_global.glitterPasskeyPasswordChange.challenge_id}}',
                                'password' => '{{$event.target.password.value}}',
                                'password_confirmation' => '{{$event.target.password_confirmation.value}}',
                            ]],
                            'onSuccess' => [
                                ['handler' => 'setState', 'params' => $clearState],
                                ['handler' => 'toast', 'params' => ['type' => 'success', 'message' => '$t:glitter-social_totp_passkey.login.passkey_password_change_success']],
                                ['handler' => 'navigate', 'params' => ['path' => '/']],
                            ],
                            'onError' => $challengeFailure,
                        ],
                    ],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'password', 'type' => 'password', 'autoComplete' => 'new-password', 'required' => true, 'disabled' => '{{_global.glitterPasskeyPasswordChangeSubmitting}}', 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.login.passkey_password_change_new']],
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'password_confirmation', 'type' => 'password', 'autoComplete' => 'new-password', 'required' => true, 'disabled' => '{{_global.glitterPasskeyPasswordChangeSubmitting}}', 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.login.passkey_password_change_confirm']],
                        ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'disabled' => '{{_global.glitterPasskeyPasswordChangeSubmitting}}', 'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 text-white disabled:opacity-50 dark:bg-gray-100 dark:text-gray-900'], 'text' => '$t:glitter-social_totp_passkey.login.passkey_password_change_submit'],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'Button',
                    'if' => '{{_global.glitterPasskeyPasswordChange.can_postpone}}',
                    'actions' => [
                        ['type' => 'click', 'handler' => 'setState', 'params' => ['target' => 'global', 'glitterPasskeyPasswordChangeSubmitting' => true]],
                        [
                            'type' => 'click',
                            'handler' => 'loginPasswordChangePostpone',
                            'target' => 'user',
                            'params' => ['body' => ['challenge_id' => '{{_global.glitterPasskeyPasswordChange.challenge_id}}']],
                            'onSuccess' => [
                                ['handler' => 'setState', 'params' => $clearState],
                                ['handler' => 'toast', 'params' => ['type' => 'info', 'message' => '$t:glitter-social_totp_passkey.login.passkey_password_change_postponed']],
                                ['handler' => 'navigate', 'params' => ['path' => '/']],
                            ],
                            'onError' => $challengeFailure,
                        ],
                    ],
                    'props' => ['type' => 'button', 'disabled' => '{{_global.glitterPasskeyPasswordChangeSubmitting}}', 'className' => 'mt-3 w-full rounded-md border border-gray-300 px-4 py-2 disabled:opacity-50 dark:border-gray-600'],
                    'text' => '$t:glitter-social_totp_passkey.login.passkey_password_change_postpone',
                ],
                [
                    'type' => 'basic',
                    'name' => 'Button',
                    'actions' => [['type' => 'click', 'handler' => 'setState', 'params' => $clearState]],
                    'props' => ['type' => 'button', 'disabled' => '{{_global.glitterPasskeyPasswordChangeSubmitting}}', 'className' => 'mt-2 w-full rounded-md border border-gray-300 px-4 py-2 disabled:opacity-50 dark:border-gray-600'],
                    'text' => '$t:glitter-social_totp_passkey.login.passkey_password_change_restart',
                ],
            ],
        ];
    }

    private function buildSocialTotpEnrollmentNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_enrollment_identity',
            'if' => '{{query?.glitter_social_totp_passkey_totp_enrollment}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.login.totp_enrollment_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.login.totp_enrollment_description'],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'target' => '/api/plugins/glitter-social_totp_passkey/totp/social-enrollment/identity',
                        'params' => [
                            'method' => 'POST',
                            'body' => [
                                'pending_id' => '{{query.glitter_social_totp_passkey_totp_enrollment}}',
                                'code' => '{{$event.target.code.value}}',
                            ],
                        ],
                        'onSuccess' => [['handler' => 'openWindow', 'target' => '{{response.redirect_url}}', 'params' => ['target' => '_self']]],
                        'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.totp_enrollment_failed']]],
                    ]],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'code', 'type' => 'text', 'inputMode' => 'numeric', 'autoComplete' => 'one-time-code', 'required' => true, 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.login.totp_enrollment_code_placeholder']],
                        ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900'], 'text' => '$t:glitter-social_totp_passkey.login.totp_enrollment_submit'],
                    ],
                ],
            ],
        ];
    }

    private function buildSocialTotpSetupNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_setup',
            'if' => '{{query?.glitter_social_totp_passkey_totp_setup && _global.socialTotpPasskeyEnrollment}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.login.totp_setup_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.login.totp_setup_description'],
                ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'manual_key', 'type' => 'text', 'readOnly' => true, 'value' => '{{_global.socialTotpPasskeyEnrollment.manual_key}}', 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 font-mono dark:border-gray-600 dark:bg-gray-800']],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'target' => '/api/plugins/glitter-social_totp_passkey/totp/social-enrollment/confirm',
                        'params' => ['method' => 'POST', 'body' => ['enrollment_id' => '{{_global.socialTotpPasskeyEnrollment.enrollment_id}}', 'code' => '{{$event.target.code.value}}']],
                        'onSuccess' => [['handler' => 'openWindow', 'target' => '{{response.redirect_url}}', 'params' => ['target' => '_self']]],
                        'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.totp_enrollment_failed']]],
                    ]],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'code', 'type' => 'text', 'inputMode' => 'numeric', 'autoComplete' => 'one-time-code', 'required' => true, 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.login.totp_enrollment_code_placeholder']],
                        ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900'], 'text' => '$t:glitter-social_totp_passkey.login.totp_enrollment_submit'],
                    ],
                ],
            ],
        ];
    }

    private function buildSocialTotpTransitionSetupNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_transition_setup',
            'if' => '{{query?.glitter_social_totp_passkey_totp_transition_setup && _global.socialTotpPasskeyTransitionEnrollment}}',
            'type' => 'basic', 'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.login.totp_setup_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.login.totp_transition_setup_description'],
                ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'manual_key', 'type' => 'text', 'readOnly' => true, 'value' => '{{_global.socialTotpPasskeyTransitionEnrollment.manual_key}}', 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 font-mono dark:border-gray-600 dark:bg-gray-800']],
                [
                    'type' => 'basic', 'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit', 'handler' => 'apiCall', 'target' => '/api/plugins/glitter-social_totp_passkey/totp/transition/enrollment/confirm',
                        'params' => ['method' => 'POST', 'body' => ['enrollment_id' => '{{_global.socialTotpPasskeyTransitionEnrollment.enrollment_id}}', 'code' => '{{$event.target.code.value}}']],
                        'onSuccess' => [['handler' => 'openWindow', 'target' => '{{response.redirect_url}}', 'params' => ['target' => '_self']]],
                        'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.totp_enrollment_failed']]],
                    ]],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'code', 'type' => 'text', 'inputMode' => 'numeric', 'autoComplete' => 'one-time-code', 'required' => true, 'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.login.totp_enrollment_code_placeholder']],
                        ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900'], 'text' => '$t:glitter-social_totp_passkey.login.totp_enrollment_submit'],
                    ],
                ],
            ],
        ];
    }

    /**
     * 신규 Social identity의 사용자 입력/약관 동의와 signup IDV 코드를 받습니다.
     * Core register template를 수정하지 않고 pending query가 있을 때만 표시합니다.
     */
    private function buildRegistrationNode(): array
    {
        $fields = [
            [
                'name' => 'registration_name',
                'type' => 'text',
                'required' => true,
                'placeholder' => '$t:glitter-social_totp_passkey.register.name_placeholder',
            ],
            [
                'name' => 'nickname',
                'type' => 'text',
                'placeholder' => '$t:glitter-social_totp_passkey.register.nickname_placeholder',
            ],
            [
                'name' => 'email',
                'type' => 'email',
                'placeholder' => '$t:glitter-social_totp_passkey.register.email_placeholder',
            ],
        ];

        $fieldNodes = [];
        foreach ($fields as $field) {
            $fieldNodes[] = [
                'type' => 'basic',
                'name' => 'Input',
                'props' => array_merge([
                    'name' => $field['name'],
                    'type' => $field['type'],
                    'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800',
                ], array_filter([
                    'required' => $field['required'] ?? null,
                    'placeholder' => $field['placeholder'] ?? null,
                ], static fn (mixed $value): bool => $value !== null)),
            ];
        }

        $fieldNodes[] = [
            'type' => 'basic',
            'name' => 'Label',
            'props' => ['className' => 'mb-2 flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300'],
            'children' => [
                [
                    'type' => 'basic',
                    'name' => 'Input',
                    'props' => ['name' => 'agree_terms', 'type' => 'checkbox', 'required' => true],
                ],
                ['type' => 'basic', 'name' => 'Span', 'text' => '$t:glitter-social_totp_passkey.register.agree_terms'],
            ],
        ];
        $fieldNodes[] = [
            'type' => 'basic',
            'name' => 'Label',
            'props' => ['className' => 'mb-3 flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300'],
            'children' => [
                [
                    'type' => 'basic',
                    'name' => 'Input',
                    'props' => ['name' => 'agree_privacy', 'type' => 'checkbox', 'required' => true],
                ],
                ['type' => 'basic', 'name' => 'Span', 'text' => '$t:glitter-social_totp_passkey.register.agree_privacy'],
            ],
        ];

        $fieldNodes[] = [
            'type' => 'basic',
            'name' => 'Button',
            'props' => [
                'type' => 'submit',
                'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900',
            ],
            'text' => '$t:glitter-social_totp_passkey.register.complete_button',
        ];

        return [
            'id' => 'glitter_social_totp_passkey_registration',
            'if' => '{{query?.glitter_social_totp_passkey_registration && !query?.glitter_social_totp_passkey_registration_idv && !query?.glitter_social_totp_passkey_registration_totp}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-gray-200 p-4 dark:border-gray-700'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.register.title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.register.description'],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'target' => '/api/plugins/glitter-social_totp_passkey/registration',
                        'params' => [
                            'method' => 'POST',
                            'body' => [
                                'pending_id' => '{{query.glitter_social_totp_passkey_registration}}',
                                'name' => '{{$event.target.registration_name.value}}',
                                'nickname' => '{{$event.target.nickname.value}}',
                                'email' => '{{$event.target.email.value}}',
                                'agree_terms' => '{{$event.target.agree_terms.checked}}',
                                'agree_privacy' => '{{$event.target.agree_privacy.checked}}',
                            ],
                        ],
                        'onSuccess' => [[
                            'handler' => 'openWindow',
                            'target' => '{{response.redirect_url}}',
                            'params' => ['target' => '_self'],
                        ]],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.register.failed'],
                        ]],
                    ]],
                    'children' => $fieldNodes,
                ],
            ],
        ];
    }

    private function buildRegistrationIdentityNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_registration_idv',
            'if' => '{{query?.glitter_social_totp_passkey_registration && query?.glitter_social_totp_passkey_registration_idv}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.register.idv_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.register.idv_description'],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'target' => '/api/plugins/glitter-social_totp_passkey/registration/idv',
                        'params' => [
                            'method' => 'POST',
                            'body' => [
                                'pending_id' => '{{query.glitter_social_totp_passkey_registration}}',
                                'code' => '{{$event.target.code.value}}',
                            ],
                        ],
                        'onSuccess' => [[
                            'handler' => 'openWindow',
                            'target' => '{{response.redirect_url}}',
                            'params' => ['target' => '_self'],
                        ]],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.register.failed'],
                        ]],
                    ]],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Input',
                            'props' => [
                                'name' => 'code',
                                'type' => 'text',
                                'inputMode' => 'numeric',
                                'autoComplete' => 'one-time-code',
                                'required' => true,
                                'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800',
                                'placeholder' => '$t:glitter-social_totp_passkey.register.idv_code_placeholder',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Button',
                            'props' => ['type' => 'submit', 'className' => 'w-full rounded-md bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900'],
                            'text' => '$t:glitter-social_totp_passkey.register.idv_submit',
                        ],
                    ],
                ],
            ],
        ];
    }

    private function buildRegistrationTotpNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_registration_totp',
            'if' => '{{query?.glitter_social_totp_passkey_registration && query?.glitter_social_totp_passkey_registration_totp && _global.socialTotpPasskeyRegistrationEnrollment}}',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mb-6 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-950/30'],
            'children' => [
                ['type' => 'basic', 'name' => 'H3', 'text' => '$t:glitter-social_totp_passkey.register.totp_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.register.totp_description'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.register.totp_qr_description'],
                ['type' => 'basic', 'name' => 'Img', 'if' => '{{_global.socialTotpPasskeyRegistrationEnrollment.enrollment.qr_data_uri}}', 'props' => [
                    'src' => '{{_global.socialTotpPasskeyRegistrationEnrollment.enrollment.qr_data_uri}}',
                    'alt' => '$t:glitter-social_totp_passkey.register.totp_qr_alt',
                    'className' => 'mb-3 h-48 w-48 rounded-md border border-green-300 bg-white p-2 dark:border-green-700',
                ]],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-2 text-sm text-gray-600 dark:text-gray-300'], 'text' => '$t:glitter-social_totp_passkey.register.totp_manual_key'],
                ['type' => 'basic', 'name' => 'Input', 'props' => [
                    'id' => 'glitter-social_totp_passkey-registration-totp-manual-key',
                    'name' => 'manual_key',
                    'type' => 'text',
                    'readOnly' => true,
                    'value' => '{{_global.socialTotpPasskeyRegistrationEnrollment.enrollment.manual_key}}',
                    'className' => 'mb-3 w-full rounded-md border border-green-300 bg-white px-2 py-1 font-mono text-sm dark:border-green-700 dark:bg-gray-900',
                ]],
                ['type' => 'basic', 'name' => 'Button', 'props' => [
                    'id' => 'glitter-social_totp_passkey-registration-totp-copy',
                    'type' => 'button',
                    'className' => 'mb-3 w-full rounded-md border border-green-300 px-3 py-2 text-sm font-medium text-green-900 dark:border-green-700 dark:text-green-100',
                ], 'text' => '$t:glitter-social_totp_passkey.register.totp_copy_key'],
                ['type' => 'basic', 'name' => 'Span', 'props' => [
                    'id' => 'glitter-social_totp_passkey-registration-totp-copy-success',
                    'className' => 'sr-only',
                ], 'text' => '$t:glitter-social_totp_passkey.register.totp_copy_success'],
                ['type' => 'basic', 'name' => 'Span', 'props' => [
                    'id' => 'glitter-social_totp_passkey-registration-totp-copy-failed',
                    'className' => 'sr-only',
                ], 'text' => '$t:glitter-social_totp_passkey.register.totp_copy_failed'],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'target' => '/api/plugins/glitter-social_totp_passkey/registration/totp/confirm',
                        'params' => [
                            'method' => 'POST',
                            'body' => [
                                'pending_id' => '{{query.glitter_social_totp_passkey_registration}}',
                                'enrollment_id' => '{{_global.socialTotpPasskeyRegistrationEnrollment.enrollment.enrollment_id}}',
                                'code' => '{{$event.target.code.value}}',
                            ],
                        ],
                        'onSuccess' => [['handler' => 'openWindow', 'target' => '{{response.redirect_url}}', 'params' => ['target' => '_self']]],
                        'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.register.totp_failed']]],
                    ]],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => [
                            'name' => 'code',
                            'type' => 'text',
                            'inputMode' => 'numeric',
                            'autoComplete' => 'one-time-code',
                            'required' => true,
                            'className' => 'mb-3 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800',
                            'placeholder' => '$t:glitter-social_totp_passkey.register.totp_code_placeholder',
                        ]],
                        ['type' => 'basic', 'name' => 'Button', 'props' => [
                            'type' => 'submit',
                            'className' => 'w-full rounded-lg bg-gray-900 px-4 py-2 font-medium text-white dark:bg-gray-100 dark:text-gray-900',
                        ], 'text' => '$t:glitter-social_totp_passkey.register.totp_submit'],
                    ],
                ],
            ],
        ];
    }

    private function ensureExchangeInitAction(array $initActions): array
    {
        foreach ($initActions as $action) {
            if (($action['_marker'] ?? null) === self::INIT_ACTION_MARKER) {
                return $initActions;
            }
        }

        // sequence 로 감싸지 않고 apiCall 을 직접 둔다 — 코어 TemplateApp::executeInitActions 는
        // init action 을 ActionDefinition 으로 옮길 때 `actions` 필드를 복사하지 않아, sequence 가
        // 빈 배열로 조용히 건너뛰어져 교환 API 가 한 번도 호출되지 않았다(실측).
        $initActions[] = [
            '_marker' => self::INIT_ACTION_MARKER,
            'if' => '{{query?.glitter_social_totp_passkey_exchange}}',
            'handler' => 'apiCall',
            'target' => '/api/plugins/glitter-social_totp_passkey/exchange',
            'params' => [
                'method' => 'POST',
                'body' => ['code' => '{{query.glitter_social_totp_passkey_exchange}}'],
            ],
            'onSuccess' => [
                [
                    'handler' => 'saveToLocalStorage',
                    'params' => ['key' => 'auth_token', 'value' => '{{response.token}}'],
                ],
                [
                    'handler' => 'replaceUrl',
                    'params' => [
                        'query' => [
                            'glitter_social_totp_passkey_exchange' => '',
                        ],
                        'mergeQuery' => true,
                    ],
                ],
                [
                    // SPA navigate 가 아니라 전체 이동(window.location.assign)이어야 한다.
                    // 코어 AuthManager 의 인증 상태(isAuthenticated)는 `login` 핸들러 내부의 private
                    // establishSession 또는 부팅 시 preloadAuth 로만 켜진다. navigate 로 이동하면
                    // 상태가 false 로 남아 DataSourceManager 가 auth_required 데이터소스(current_user)를
                    // 건너뛰고 fallback 으로 _global.currentUser 를 덮어써, 새로고침 전까지 비로그인처럼
                    // 보였다(실측). 전체 이동은 부팅 preloadAuth 를 거쳐 저장된 토큰으로 상태를 복원한다.
                    'handler' => 'openWindow',
                    // 서버가 검증한 값만 쓴다(쿼리스트링의 redirect 는 읽지 않음).
                    'target' => '{{response.redirect_path ?? \'/\'}}',
                    'params' => ['target' => '_self'],
                ],
            ],
            'onError' => [
                [
                    'handler' => 'replaceUrl',
                    'params' => [
                        'query' => [
                            'glitter_social_totp_passkey_exchange' => '',
                        ],
                        'mergeQuery' => true,
                    ],
                ],
                [
                    'handler' => 'toast',
                    'params' => ['type' => 'error', 'message' => '$t:auth.login_failed'],
                ],
            ],
        ];

        return [...$initActions, ...$this->socialErrorToasts()];
    }

    private function ensureSocialTotpSetupInitAction(array $initActions): array
    {
        foreach ($initActions as $action) {
            if (($action['_marker'] ?? null) === 'glitter_social_totp_passkey_setup') {
                return $initActions;
            }
        }

        $initActions[] = [
            '_marker' => 'glitter_social_totp_passkey_setup',
            'if' => '{{query?.glitter_social_totp_passkey_totp_setup}}',
            'handler' => 'apiCall',
            'target' => '/api/plugins/glitter-social_totp_passkey/totp/social-enrollment',
            'params' => ['method' => 'POST', 'body' => []],
            'onSuccess' => [['handler' => 'setState', 'params' => ['target' => 'global', 'socialTotpPasskeyEnrollment' => '{{response}}']]],
            'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.totp_enrollment_failed']]],
        ];

        return $initActions;
    }

    private function ensureSocialTotpTransitionInitAction(array $initActions): array
    {
        foreach ($initActions as $action) {
            if (($action['_marker'] ?? null) === 'glitter_social_totp_passkey_transition_setup') return $initActions;
        }
        $initActions[] = [
            '_marker' => 'glitter_social_totp_passkey_transition_setup',
            'if' => '{{query?.glitter_social_totp_passkey_totp_transition_setup}}',
            'handler' => 'apiCall',
            'target' => '/api/plugins/glitter-social_totp_passkey/totp/transition/enrollment',
            'params' => ['method' => 'POST', 'body' => []],
            'onSuccess' => [['handler' => 'setState', 'params' => ['target' => 'global', 'socialTotpPasskeyTransitionEnrollment' => '{{response}}']]],
            'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.login.totp_enrollment_failed']]],
        ];
        return $initActions;
    }

    private function ensureSocialRegistrationTotpInitAction(array $initActions): array
    {
        foreach ($initActions as $action) {
            if (($action['_marker'] ?? null) === 'glitter_social_totp_passkey_registration_totp') {
                return $initActions;
            }
        }

        $initActions[] = [
            '_marker' => 'glitter_social_totp_passkey_registration_totp',
            'if' => '{{query?.glitter_social_totp_passkey_registration_totp && query?.glitter_social_totp_passkey_registration}}',
            'handler' => 'apiCall',
            'target' => '/api/plugins/glitter-social_totp_passkey/registration/totp',
            'params' => [
                'method' => 'POST',
                'body' => ['pending_id' => '{{query.glitter_social_totp_passkey_registration}}'],
            ],
            'onSuccess' => [['handler' => 'setState', 'params' => ['target' => 'global', 'socialTotpPasskeyRegistrationEnrollment' => '{{response}}']]],
            'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.register.totp_failed']]],
        ];

        return $initActions;
    }

    /**
     * `glitter_social_totp_passkey_error` 쿼리 안내 토스트.
     *
     * 기존 오류 코드는 지금처럼 코드 그대로 보여 주되, 보안상 사용자에게 안내해야
     * 하는 2FA 차단과 제한 초과는 번역 문구로 표시한다.
     *
     * @return array<int, array>
     */
    private function socialErrorToasts(): array
    {
        $code = SocialLoginRateLimiters::ERROR_CODE;
        $twoFactorCode = 'two_factor_required';
        $twoFactorFailedCode = 'two_factor_failed';
        $registrationPendingCode = 'registration_pending';
        return [
            [
                'if' => "{{query?.glitter_social_totp_passkey_error && query.glitter_social_totp_passkey_error !== '{$code}' && query.glitter_social_totp_passkey_error !== '{$twoFactorCode}' && query.glitter_social_totp_passkey_error !== '{$twoFactorFailedCode}' && query.glitter_social_totp_passkey_error !== '{$registrationPendingCode}'}}",
                'handler' => 'toast',
                'params' => [
                    'type' => 'error',
                    'message' => '{{query.glitter_social_totp_passkey_error}}',
                ],
            ],
            [
                'if' => "{{query?.glitter_social_totp_passkey_error === '{$code}'}}",
                'handler' => 'toast',
                'params' => [
                    'type' => 'error',
                    'message' => '$t:glitter-social_totp_passkey.login.too_many_attempts',
                ],
            ],
            [
                'if' => "{{query?.glitter_social_totp_passkey_error === '{$twoFactorCode}'}}",
                'handler' => 'toast',
                'params' => [
                    'type' => 'error',
                    'message' => '$t:glitter-social_totp_passkey.login.two_factor_required',
                ],
            ],
            [
                'if' => "{{query?.glitter_social_totp_passkey_error === '{$twoFactorFailedCode}'}}",
                'handler' => 'toast',
                'params' => [
                    'type' => 'error',
                    'message' => '$t:glitter-social_totp_passkey.login.two_factor_failed',
                ],
            ],
            [
                'if' => "{{query?.glitter_social_totp_passkey_error === '{$registrationPendingCode}'}}",
                'handler' => 'toast',
                'params' => [
                    'type' => 'info',
                    'message' => '$t:glitter-social_totp_passkey.login.registration_pending',
                ],
            ],
        ];
    }

    /**
     * @param  array<int, array>  $nodes
     */
    private function treeHasNodeId(array $nodes, string $id): bool
    {
        foreach ($nodes as $node) {
            if (! is_array($node)) {
                continue;
            }

            if (($node['id'] ?? null) === $id) {
                return true;
            }

            if (isset($node['children']) && is_array($node['children']) && $this->treeHasNodeId($node['children'], $id)) {
                return true;
            }
        }

        return false;
    }
}
