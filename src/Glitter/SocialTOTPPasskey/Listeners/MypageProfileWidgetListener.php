<?php

namespace Glitter\SocialTOTPPasskey\Listeners;

use App\Contracts\Extension\HookListenerInterface;
use Illuminate\Support\Facades\Log;
use Glitter\SocialTOTPPasskey\Services\SocialAuthService;
use Glitter\SocialTOTPPasskey\Support\BrandIcons;

/**
 * 마이페이지 프로필 화면(`mypage/profile`)에 "연동된 소셜 계정" 카드를
 * `core.layout_extension.after_apply` 로 주입한다. 앵커는 프로필 뷰의
 * "서명 및 자기소개 카드"(id: profile_view_bio_card, sirsoft-basic 코어 원본) —
 * 그 바로 앞에 splice 한다.
 */
class MypageProfileWidgetListener implements HookListenerInterface
{
    public function __construct(private readonly SocialAuthService $socialAuth) {}

    private const WIDGET_ID = 'glitter_social_totp_passkey_profile_widget';

    private const API_PREFIX = '/api/plugins/glitter-social_totp_passkey';

    private const ANCHOR_ID = 'profile_view_bio_card';

    private const DATA_SOURCE_ID = 'glitter_social_totp_passkey_accounts';

    private const PASSKEY_DATA_SOURCE_ID = 'glitter_social_totp_passkey_credentials';

    private const TOAST_MARKER = 'glitter_social_totp_passkey_link_toast';

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
        if (($layout['layout_name'] ?? null) !== 'mypage/profile') {
            return $layout;
        }

        if (! isset($layout['components']) || ! is_array($layout['components'])) {
            return $layout;
        }

        if (! $this->treeHasNodeId($layout['components'], self::WIDGET_ID)) {
            $injected = 0;
            $layout['components'] = $this->spliceBeforeAnchor($layout['components'], $injected);

            if ($injected === 0) {
                Log::channel('glitter_social_totp_passkey')->error('[glitter-social_totp_passkey] 프로필 화면 앵커(profile_view_bio_card)를 찾지 못해 소셜 연동 위젯을 주입하지 못했습니다. sirsoft-basic mypage/profile 레이아웃 구조 변경 여부 확인 필요.', [
                    'template_id' => $templateId,
                ]);
            }
        }

        $layout['data_sources'] = $this->ensurePasskeyDataSource($this->ensureDataSource($layout['data_sources'] ?? []));
        $layout['initActions'] = $this->ensureLinkToast($layout['initActions'] ?? []);

        return $layout;
    }

    private function spliceBeforeAnchor(array $nodes, int &$injected): array
    {
        $anchorIndex = null;

        foreach ($nodes as $index => $node) {
            if (is_array($node) && ($node['id'] ?? null) === self::ANCHOR_ID) {
                $anchorIndex = $index;
                break;
            }
        }

        if ($anchorIndex !== null) {
            array_splice($nodes, $anchorIndex, 0, [$this->buildWidgetNode()]);
            $injected++;

            return $nodes;
        }

        foreach ($nodes as &$node) {
            if (is_array($node) && isset($node['children']) && is_array($node['children'])) {
                $node['children'] = $this->spliceBeforeAnchor($node['children'], $injected);

                if ($injected > 0) {
                    break;
                }
            }
        }

        return $nodes;
    }

    private function buildWidgetNode(): array
    {
        return [
            'id' => self::WIDGET_ID,
            'comment' => 'glitter-social_totp_passkey: 연동된 소셜 계정',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6'],
            'responsive' => ['portable' => ['props' => ['className' => 'bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4']]],
            'children' => [
                [
                    'type' => 'basic', 'name' => 'H3',
                    'props' => ['className' => 'text-base font-semibold text-gray-900 dark:text-white mb-4 pb-3 border-b border-gray-200 dark:border-gray-700'],
                    'text' => '$t:glitter-social_totp_passkey.profile.section_title',
                ],
                [
                    'type' => 'basic', 'name' => 'Div',
                    'props' => ['className' => 'space-y-3'],
                    'children' => array_map(
                        fn (string $provider): array => $this->buildProviderRow($provider),
                        $this->socialAuth->orderedProviders(),
                    ),
                ],
                $this->buildPasskeyNode(),
                $this->buildTotpNode(),
            ],
        ];
    }

    private function buildPasskeyNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey_management',
            'if' => "{{_global.plugins?.['glitter-social_totp_passkey']?.passkey_enabled}}",
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mt-6 border-t border-gray-200 pt-5 dark:border-gray-700'],
            'children' => [
                ['type' => 'basic', 'name' => 'H4', 'props' => ['className' => 'text-sm font-semibold text-gray-900 dark:text-white'], 'text' => '$t:glitter-social_totp_passkey.profile.passkey_title'],
                ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'mb-3 text-xs text-gray-500 dark:text-gray-400'], 'text' => '$t:glitter-social_totp_passkey.profile.passkey_description'],
                [
                    'type' => 'basic', 'name' => 'Button',
                    'if' => '{{!!'.self::PASSKEY_DATA_SOURCE_ID.' && !_dataSourceErrors?.'.self::PASSKEY_DATA_SOURCE_ID.' && ('.self::PASSKEY_DATA_SOURCE_ID.'.data ?? []).length > 0}}',
                    'props' => ['type' => 'button', 'className' => 'mb-3 rounded-md border border-gray-300 px-3 py-2 text-sm dark:border-gray-600'],
                    'text' => '$t:glitter-social_totp_passkey.profile.passkey_reauthenticate',
                    'actions' => [[
                        'type' => 'click', 'handler' => 'glitter-social_totp_passkey.passkeyReauthenticate',
                        'params' => ['purpose' => 'reauth'],
                        'errorHandling' => ['-1' => ['handler' => 'suppress']],
                    ]],
                ],
                [
                    'type' => 'basic', 'name' => 'Form',
                    'if' => "{{!!_global.socialTotpPasskeyReauthToken && !!_global.socialTotpPasskeyReauthExpiresAt && _global.plugins?.['glitter-social_totp_passkey']?.passkey_registration_enabled}}",
                    'actions' => [[
                        'type' => 'submit', 'handler' => 'glitter-social_totp_passkey.passkeyRegister',
                        'params' => [
                            'reauthToken' => '{{_global.socialTotpPasskeyReauthToken}}',
                            'name' => '{{$event.target.passkey_name.value}}',
                        ],
                    ]],
                    'children' => [
                        ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'passkey_name', 'type' => 'text', 'required' => true, 'maxLength' => 100, 'className' => 'mb-2 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.profile.passkey_name_placeholder']],
                        ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'className' => 'rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white dark:bg-gray-100 dark:text-gray-900'], 'text' => '$t:glitter-social_totp_passkey.profile.passkey_register'],
                    ],
                ],
                [
                    'type' => 'basic', 'name' => 'P',
                    'if' => '{{!_global.socialTotpPasskeyReauthToken || !_global.socialTotpPasskeyReauthExpiresAt}}',
                    'props' => ['className' => 'mt-3 text-xs text-gray-500 dark:text-gray-400'],
                    'text' => '$t:glitter-social_totp_passkey.profile.passkey_management_reauthentication_required',
                ],
                [
                    'type' => 'basic', 'name' => 'P',
                    'if' => '{{!!'.self::PASSKEY_DATA_SOURCE_ID.' && !_dataSourceErrors?.'.self::PASSKEY_DATA_SOURCE_ID.' && ('.self::PASSKEY_DATA_SOURCE_ID.'.data ?? []).length === 0}}',
                    'props' => ['className' => 'mt-3 text-xs text-gray-500 dark:text-gray-400'],
                    'text' => '$t:glitter-social_totp_passkey.profile.passkey_empty',
                ],
                [
                    'type' => 'basic', 'name' => 'P',
                    'if' => '{{!!_dataSourceErrors?.'.self::PASSKEY_DATA_SOURCE_ID.'}}',
                    'props' => ['className' => 'mt-3 text-xs text-red-600 dark:text-red-400'],
                    'text' => '$t:glitter-social_totp_passkey.profile.passkey_load_failed',
                ],
                [
                    'type' => 'basic', 'name' => 'Div',
                    'props' => ['className' => 'mt-3 space-y-2'],
                    'iteration' => ['source' => self::PASSKEY_DATA_SOURCE_ID.'.data ?? []', 'item_var' => 'credential'],
                    'children' => [[
                        'type' => 'basic', 'name' => 'Div',
                        'props' => ['className' => 'rounded-md border border-gray-200 p-3 dark:border-gray-700'],
                        'children' => [
                            ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'text-sm font-medium'], 'text' => '{{credential.name}}'],
                            ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'text-xs text-gray-500'], 'text' => '$t:glitter-social_totp_passkey.profile.passkey_created_at|date={{credential.created_at}}'],
                            ['type' => 'basic', 'name' => 'P', 'props' => ['className' => 'text-xs text-gray-500'], 'text' => '$t:glitter-social_totp_passkey.profile.passkey_last_used_at|date={{credential.last_used_at ?? \'-\'}}'],
                            [
                                'type' => 'basic', 'name' => 'Form', 'props' => ['className' => 'mt-2 flex gap-2'],
                                'actions' => [[
                                    'type' => 'submit', 'handler' => 'apiCall', 'auth_required' => true,
                                    'target' => self::API_PREFIX.'/passkey/credentials/{{credential.id}}',
                                    'params' => ['method' => 'PATCH', 'body' => ['name' => '{{$event.target.passkey_name.value}}']],
                                    'onSuccess' => [['handler' => 'refetchDataSource', 'params' => ['dataSourceId' => self::PASSKEY_DATA_SOURCE_ID]]],
                                    'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.passkey_failed']]],
                                ]],
                                'children' => [
                                    ['type' => 'basic', 'name' => 'Input', 'props' => ['name' => 'passkey_name', 'type' => 'text', 'required' => true, 'value' => '{{credential.name}}', 'className' => 'min-w-0 flex-1 rounded-md border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-800']],
                                    ['type' => 'basic', 'name' => 'Button', 'props' => ['type' => 'submit', 'className' => 'rounded-md border border-gray-300 px-2 py-1 text-xs dark:border-gray-600'], 'text' => '$t:glitter-social_totp_passkey.profile.passkey_rename'],
                                ],
                            ],
                            [
                                'type' => 'basic', 'name' => 'Button',
                                'if' => '{{!!_global.socialTotpPasskeyReauthToken && !!_global.socialTotpPasskeyReauthExpiresAt}}',
                                'props' => ['type' => 'button', 'className' => 'mt-2 text-xs text-red-600 dark:text-red-400'],
                                'text' => '$t:glitter-social_totp_passkey.profile.passkey_delete',
                                'actions' => [[
                                    'type' => 'click', 'handler' => 'glitter-social_totp_passkey.passkeyDelete',
                                    'params' => [
                                        'credentialId' => '{{credential.id}}',
                                        'reauthToken' => '{{_global.socialTotpPasskeyReauthToken}}',
                                    ],
                                    'onSuccess' => [['handler' => 'refetchDataSource', 'params' => ['dataSourceId' => self::PASSKEY_DATA_SOURCE_ID]]],
                                    'onError' => [[
                                        'handler' => 'toast',
                                        'params' => ['type' => 'error', 'message' => '{{error.message}}'],
                                    ]],
                                ]],
                            ],
                        ],
                    ]],
                ],
            ],
        ];
    }

    private function buildTotpNode(): array
    {
        return [
            'id' => 'glitter_social_totp_passkey',
            'type' => 'basic',
            'name' => 'Div',
            'props' => ['className' => 'mt-6 border-t border-gray-200 pt-5 dark:border-gray-700'],
            'children' => [
                [
                    'type' => 'basic',
                    'name' => 'H4',
                    'props' => ['className' => 'text-sm font-semibold text-gray-900 dark:text-white'],
                    'text' => '$t:glitter-social_totp_passkey.profile.totp_title',
                ],
                [
                    'type' => 'basic',
                    'name' => 'P',
                    'props' => ['className' => 'mt-1 mb-3 text-xs text-gray-500 dark:text-gray-400'],
                    'text' => '$t:glitter-social_totp_passkey.profile.totp_description',
                ],
                [
                    'type' => 'basic',
                    'name' => 'P',
                    'props' => ['className' => 'mb-3 text-xs font-medium text-green-600 dark:text-green-400'],
                    'if' => '{{glitter_social_totp_passkey_accounts.data?.totp_enabled === true}}',
                    'text' => '$t:glitter-social_totp_passkey.profile.totp_enabled',
                ],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'dataKey' => 'glitterSocialTotpPasskeyReauth',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'glitter-social_totp_passkey.passkeyPasswordReauthenticate',
                        'params' => ['password' => '{{$event.target.password.value}}'],
                        'errorHandling' => ['-1' => ['handler' => 'suppress']],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.totp_reauth_failed'],
                        ]],
                    ]],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Input',
                            'props' => [
                                'name' => 'password',
                                'type' => 'password',
                                'autoComplete' => 'current-password',
                                'required' => true,
                                'className' => 'mb-2 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800',
                                'placeholder' => '$t:glitter-social_totp_passkey.profile.totp_password_placeholder',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Button',
                            'props' => ['type' => 'submit', 'className' => 'rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white dark:bg-gray-100 dark:text-gray-900'],
                            'text' => '$t:glitter-social_totp_passkey.profile.totp_reauth_button',
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'if' => '{{!!_global.socialTotpPasskeyReauthToken}}',
                    'dataKey' => 'glitterSocialTotpPasskeyEnrollment',
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'apiCall',
                        'auth_required' => true,
                        'target' => '/api/plugins/glitter-social_totp_passkey/totp/enrollment',
                        'params' => [
                            'method' => 'POST',
                            'body' => [
                                'reauth_token' => '{{_global.socialTotpPasskeyReauthToken}}',
                                'current_code' => '{{$event.target.current_code.value}}',
                            ],
                        ],
                        'onSuccess' => [[
                            'handler' => 'setState',
                            'params' => ['target' => 'global', 'socialTotpPasskeyEnrollment' => '{{response}}'],
                        ]],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.totp_enrollment_failed'],
                        ]],
                    ]],
                    'children' => [
                        [
                            'type' => 'basic',
                            'name' => 'Input',
                            'props' => [
                                'name' => 'current_code',
                                'type' => 'text',
                                'inputMode' => 'numeric',
                                'autoComplete' => 'one-time-code',
                                'className' => 'mt-3 mb-2 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800',
                                'placeholder' => '$t:glitter-social_totp_passkey.profile.totp_current_code_placeholder',
                            ],
                        ],
                        [
                            'type' => 'basic',
                            'name' => 'Button',
                            'props' => ['type' => 'submit', 'className' => 'rounded-md border border-gray-300 px-3 py-2 text-sm dark:border-gray-600'],
                            'text' => '$t:glitter-social_totp_passkey.profile.totp_start_button',
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'Div',
                    'if' => '{{!!_global.socialTotpPasskeyEnrollment}}',
                    'props' => ['className' => 'mt-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-700 dark:bg-amber-900/20'],
                    'children' => [
                        ['type' => 'basic', 'name' => 'P', 'text' => '$t:glitter-social_totp_passkey.profile.totp_manual_key'],
                        [
                            'type' => 'basic',
                            'name' => 'Input',
                            'props' => [
                                'name' => 'manual_key',
                                'type' => 'text',
                                'readOnly' => true,
                                'value' => '{{_global.socialTotpPasskeyEnrollment.manual_key}}',
                                'className' => 'my-2 w-full rounded-md border border-amber-300 bg-white px-2 py-1 font-mono text-sm dark:border-amber-700 dark:bg-gray-900',
                            ],
                        ],
                        ['type' => 'basic', 'name' => 'P', 'text' => '$t:glitter-social_totp_passkey.profile.totp_confirm_hint'],
                        [
                            'type' => 'basic',
                            'name' => 'Form',
                            'actions' => [[
                                'type' => 'submit',
                                'handler' => 'apiCall',
                                'auth_required' => true,
                                'target' => '/api/plugins/glitter-social_totp_passkey/totp/enrollment/confirm',
                                'params' => [
                                    'method' => 'POST',
                                    'body' => [
                                        'reauth_token' => '{{_global.socialTotpPasskeyReauthToken}}',
                                        'enrollment_id' => '{{_global.socialTotpPasskeyEnrollment.enrollment_id}}',
                                        'code' => '{{$event.target.code.value}}',
                                    ],
                                ],
                                'onSuccess' => [
                                    ['handler' => 'setState', 'params' => ['target' => 'global', 'socialTotpPasskeyEnrollment' => null]],
                                    ['handler' => 'refetchDataSource', 'params' => ['dataSourceId' => self::DATA_SOURCE_ID]],
                                ],
                                'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.totp_enrollment_failed']]],
                            ]],
                            'children' => [[
                                'type' => 'basic',
                                'name' => 'Input',
                                'props' => ['name' => 'code', 'type' => 'text', 'inputMode' => 'numeric', 'required' => true, 'className' => 'my-2 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.profile.totp_code_placeholder'],
                            ], [
                                'type' => 'basic',
                                'name' => 'Button',
                                'props' => ['type' => 'submit', 'className' => 'rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white dark:bg-gray-100 dark:text-gray-900'],
                                'text' => '$t:glitter-social_totp_passkey.profile.totp_confirm_button',
                            ]],
                        ],
                    ],
                ],
                [
                    'type' => 'basic',
                    'name' => 'Button',
                    'if' => '{{!!_global.socialTotpPasskeyEnrollment}}',
                    'props' => ['type' => 'button', 'className' => 'mt-2 text-xs text-gray-600 underline dark:text-gray-400'],
                    'text' => '$t:glitter-social_totp_passkey.profile.totp_cancel_button',
                    'actions' => [[
                        'type' => 'click',
                        'handler' => 'setState',
                        'params' => ['target' => 'global', 'socialTotpPasskeyEnrollment' => null],
                    ]],
                ],
                [
                    'type' => 'basic',
                    'name' => 'Form',
                    'if' => '{{!!_global.socialTotpPasskeyReauthToken}}',
                    'props' => ['className' => 'mt-3'],
                    'actions' => [[
                        'type' => 'submit',
                        'handler' => 'glitter-social_totp_passkey.totpDisable',
                        'params' => [
                            'reauthToken' => '{{_global.socialTotpPasskeyReauthToken}}',
                            'code' => '{{$event.target.code.value}}',
                        ],
                        'onSuccess' => [
                            ['handler' => 'refetchDataSource', 'params' => ['dataSourceId' => self::DATA_SOURCE_ID]],
                        ],
                        'onError' => [['handler' => 'toast', 'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.totp_disable_failed']]],
                    ]],
                    'children' => [[
                        'type' => 'basic',
                        'name' => 'Input',
                        'props' => ['name' => 'code', 'type' => 'text', 'inputMode' => 'numeric', 'required' => true, 'className' => 'mt-3 mb-2 w-full rounded-md border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800', 'placeholder' => '$t:glitter-social_totp_passkey.profile.totp_code_placeholder'],
                    ], [
                        'type' => 'basic',
                        'name' => 'Button',
                        'props' => ['type' => 'submit', 'className' => 'rounded-md border border-red-300 px-3 py-2 text-sm text-red-600 dark:border-red-700 dark:text-red-400'],
                        'text' => '$t:glitter-social_totp_passkey.profile.totp_disable_button',
                    ]],
                ],
            ],
        ];
    }

    private function buildProviderRow(string $provider): array
    {
        // 순수 불리언 표현식(중괄호 없음) — 사용처마다 필요한 형태로 직접 {{ }}로 감싼다.
        // 미리 감싸두면 삼항식 등에 재사용할 때 {{ }} 가 중첩/분리되어 깨진 바인딩이 된다
        // (실측: className/text/if 세 곳에서 이 문제로 상태 텍스트와 "연동하기" 버튼이
        // 전혀 렌더되지 않는 침묵 실패가 있었음).
        $isLinked = '('.self::DATA_SOURCE_ID.".data?.linked_providers ?? []).includes('{$provider}')";
        $isLinkedExpr = "{{{$isLinked}}}";
        $enabledExpr = "{{_global.plugins?.['glitter-social_totp_passkey']?.{$provider}_enabled}}";

        $providerIcon = match ($provider) {
            'naver' => BrandIcons::naverDataUri(),
            'kakao' => BrandIcons::kakaoDataUri(),
            'google' => BrandIcons::googleDataUri(),
            'facebook' => BrandIcons::facebookDataUri(),
            'github' => BrandIcons::githubDataUri(),
            default => null,
        };

        $identityChildren = [];

        if ($providerIcon !== null) {
            $identityChildren[] = [
                'type' => 'basic', 'name' => 'Img',
                'props' => [
                    'src' => $providerIcon,
                    'alt' => '',
                    'className' => 'w-6 h-6 flex-shrink-0',
                ],
            ];
        }

        $identityChildren[] = [
            'type' => 'basic', 'name' => 'Div',
            'children' => [
                [
                    'type' => 'basic', 'name' => 'Span',
                    'props' => ['className' => 'block text-sm font-medium text-gray-900 dark:text-white'],
                    'text' => "\$t:glitter-social_totp_passkey.profile.{$provider}",
                ],
                [
                    'type' => 'basic', 'name' => 'Span',
                    'props' => ['className' => "{{{$isLinked} ? 'block text-xs text-green-600 dark:text-green-400' : 'block text-xs text-gray-400 dark:text-gray-500'}}"],
                    'text' => "{{{$isLinked} ? \$t('glitter-social_totp_passkey.profile.linked') : \$t('glitter-social_totp_passkey.profile.not_linked')}}",
                ],
            ],
        ];

        return [
            'type' => 'basic', 'name' => 'Div',
            'if' => $enabledExpr,
            'props' => ['className' => 'flex items-center justify-between p-3 border border-gray-200 dark:border-gray-700 rounded-lg'],
            'children' => [
                [
                    'type' => 'basic', 'name' => 'Div',
                    'props' => ['className' => 'flex items-center gap-3'],
                    'children' => $identityChildren,
                ],
                [
                    'type' => 'basic', 'name' => 'Button',
                    'if' => "{{!({$isLinked})}}",
                    'props' => [
                        'type' => 'button',
                        'className' => 'inline-flex items-center gap-2 px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors',
                    ],
                    'text' => "{{'(' + \$t('glitter-social_totp_passkey.profile.{$provider}') + ') ' + \$t('glitter-social_totp_passkey.profile.link_button')}}",
                    'actions' => [[
                        'type' => 'click',
                        'handler' => 'apiCall',
                        'auth_required' => true,
                        'target' => "/api/plugins/glitter-social_totp_passkey/{$provider}/link/prepare",
                        'params' => ['method' => 'POST'],
                        'onSuccess' => [[
                            'handler' => 'openWindow',
                            'target' => '{{response.data.redirect_url}}',
                            'params' => ['target' => '_self'],
                        ]],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.operation_failed'],
                        ]],
                    ]],
                ],
                [
                    'type' => 'basic', 'name' => 'Button',
                    'if' => $isLinkedExpr,
                    'props' => [
                        'type' => 'button',
                        'className' => 'inline-flex items-center gap-2 px-3 py-1.5 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-lg text-sm font-medium hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors',
                    ],
                    'text' => "{{'(' + \$t('glitter-social_totp_passkey.profile.{$provider}') + ') ' + \$t('glitter-social_totp_passkey.profile.unlink_button')}}",
                    'actions' => [[
                        'type' => 'click',
                        'handler' => 'apiCall',
                        'auth_required' => true,
                        'target' => "/api/plugins/glitter-social_totp_passkey/{$provider}/unlink",
                        'params' => ['method' => 'DELETE'],
                        'confirm' => '$t:glitter-social_totp_passkey.profile.unlink_confirm',
                        'onSuccess' => [
                            ['handler' => 'toast', 'params' => ['type' => 'success', 'message' => '$t:glitter-social_totp_passkey.profile.unlink_success']],
                            ['handler' => 'refetchDataSource', 'params' => ['dataSourceId' => self::DATA_SOURCE_ID]],
                        ],
                        'onError' => [[
                            'handler' => 'toast',
                            'params' => ['type' => 'error', 'message' => '$t:glitter-social_totp_passkey.profile.operation_failed'],
                        ]],
                    ]],
                ],
            ],
        ];
    }

    private function ensureDataSource(array $dataSources): array
    {
        foreach ($dataSources as $ds) {
            if (($ds['id'] ?? null) === self::DATA_SOURCE_ID) {
                return $dataSources;
            }
        }

        $dataSources[] = [
            'id' => self::DATA_SOURCE_ID,
            'type' => 'api',
            'endpoint' => '/api/plugins/glitter-social_totp_passkey/accounts',
            'method' => 'GET',
            'auto_fetch' => true,
            'auth_required' => true,
            'loading_strategy' => 'progressive',
            'fallback' => ['data' => ['linked_providers' => []]],
        ];

        return $dataSources;
    }

    private function ensurePasskeyDataSource(array $dataSources): array
    {
        foreach ($dataSources as $dataSource) {
            if (($dataSource['id'] ?? null) === self::PASSKEY_DATA_SOURCE_ID) {
                return $dataSources;
            }
        }

        $dataSources[] = [
            'id' => self::PASSKEY_DATA_SOURCE_ID,
            'type' => 'api',
            'endpoint' => self::API_PREFIX.'/passkey/credentials',
            'method' => 'GET',
            'auto_fetch' => true,
            'auth_required' => true,
            'loading_strategy' => 'progressive',
        ];

        return $dataSources;
    }

    private function ensureLinkToast(array $initActions): array
    {
        foreach ($initActions as $action) {
            if (($action['_marker'] ?? null) === self::TOAST_MARKER) {
                return $initActions;
            }
        }

        $initActions[] = [
            '_marker' => self::TOAST_MARKER,
            'if' => "{{query?.glitter_social_totp_passkey_link === 'success'}}",
            'handler' => 'toast',
            'params' => ['type' => 'success', 'message' => '$t:glitter-social_totp_passkey.profile.link_success'],
        ];

        $initActions[] = [
            'if' => "{{query?.glitter_social_totp_passkey_link === 'error'}}",
            'handler' => 'toast',
            'params' => ['type' => 'error', 'message' => '{{query.glitter_social_totp_passkey_error ?? \'\'}}'],
        ];

        return $initActions;
    }

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
