<?php

namespace Glitter\SocialTOTPPasskey\Listeners;

use App\Contracts\Extension\HookListenerInterface;
use App\Models\User;
use Illuminate\Support\Facades\Log;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;

/**
 * 소셜 전용 가입자(실비밀번호 없음)에게 마이페이지 프로필 편집 폼을 비밀번호 확인 없이 연다.
 *
 * 코어 `PUT /api/me` 는 이름 등 일반 항목 변경에 현재 비밀번호를 요구하지 않는다
 * (`current_password` 는 `required_with:password`). 막는 것은 템플릿 레이아웃의 화면 흐름 —
 * `_local.isPasswordVerified` 가 `POST /api/me/verify-password` 성공 시에만 true 가 되고, 편집
 * 폼 전체가 그 조건으로 가려져 있다. 소셜 가입자는 랜덤 해시 비밀번호라 이 확인을 통과할 수 없다.
 *
 * - `core.user.filter_resource_data`: `/api/me`·`/api/auth/user` 응답에 실비밀번호 보유 여부
 *   불리언 하나만 추가한다.
 * - `core.layout_extension.after_apply`: `mypage/profile-edit` 의 두 게이트 노드 `if` 를
 *   "기존 조건 OR 플래그가 명시적으로 false" 로 바꾼다. 플래그가 없거나(플러그인 비활성·응답
 *   로드 전) true 면 기존 동작 그대로(fail-closed).
 *
 * 비밀번호 변경(`PUT /api/me/password`)의 `current_password` 규칙은 건드리지 않는다.
 */
class ProfileEditPasswordGateListener implements HookListenerInterface
{
    public const RESOURCE_FIELD = 'glitter_social_totp_passkey_has_real_password';

    private const LAYOUT_NAME = 'mypage/profile-edit';

    /** 템플릿(wc-community / sirsoft-basic 계열) 원본의 게이트 노드 식별 정보 — meta.description + 원래 if */
    private const EDIT_FORM_DESCRIPTION = '마이페이지 프로필 Edit 모드 (시안 기반 카드 분리 레이아웃)';

    private const EDIT_FORM_ORIGINAL_IF = '{{_local?.isPasswordVerified}}';

    private const VERIFY_SECTION_DESCRIPTION = '프로필 편집 전 비밀번호 검증 섹션';

    private const VERIFY_SECTION_ORIGINAL_IF = '{{!_local?.isPasswordVerified}}';

    public static function getSubscribedHooks(): array
    {
        return [
            'core.user.filter_resource_data' => [
                'method' => 'filterResourceData',
                'priority' => 20,
                'type' => 'filter',
            ],
            'core.layout_extension.after_apply' => [
                'method' => 'rewriteProfileEditGate',
                'priority' => 20,
                'type' => 'filter',
            ],
        ];
    }

    public function handle(...$args): void {}

    /**
     * 행 부재 = 실비밀번호 있음(코어 가입·관리자 생성 회원). 행 존재 시 has_real_password 값.
     */
    public function filterResourceData(array $data, $user = null): array
    {
        if (! $user instanceof User) {
            return $data;
        }

        $flag = SocialLoginUserFlag::where('user_id', $user->id)->first();

        $data[self::RESOURCE_FIELD] = $flag === null || (bool) $flag->has_real_password;

        return $data;
    }

    public function rewriteProfileEditGate(array $layout, int $templateId = 0): array
    {
        if (($layout['layout_name'] ?? null) !== self::LAYOUT_NAME) {
            return $layout;
        }

        if (! isset($layout['components']) || ! is_array($layout['components'])) {
            Log::channel('glitter_social_totp_passkey')->warning('[glitter-social_totp_passkey] mypage/profile-edit 레이아웃에 components 가 없어 비밀번호 게이트를 재작성하지 않았습니다.', [
                'template_id' => $templateId,
            ]);

            return $layout;
        }

        $editIf = $this->editFormIf();
        $verifyIf = $this->verifySectionIf();

        $found = ['edit' => 0, 'verify' => 0];
        $rewritten = $this->rewriteNodes($layout['components'], $found, $editIf, $verifyIf);

        // 두 노드를 정확히 하나씩 찾았을 때만 반영한다. 한쪽만 바꾸면 폼과 확인 섹션이 동시에
        // 보이거나 둘 다 사라지는 깨진 화면이 되므로, 그보다는 원래 동작(비밀번호 확인)이 낫다.
        if ($found['edit'] !== 1 || $found['verify'] !== 1) {
            Log::channel('glitter_social_totp_passkey')->warning('[glitter-social_totp_passkey] mypage/profile-edit 비밀번호 게이트 노드를 찾지 못해 원본 레이아웃을 그대로 사용합니다. 템플릿 레이아웃 구조 변경 여부 확인 필요.', [
                'template_id' => $templateId,
                'edit_form_matches' => $found['edit'],
                'verify_section_matches' => $found['verify'],
            ]);

            return $layout;
        }

        $layout['components'] = $rewritten;

        return $layout;
    }

    /**
     * @param  array<int|string, mixed>  $nodes
     * @param  array{edit: int, verify: int}  $found
     * @return array<int|string, mixed>
     */
    private function rewriteNodes(array $nodes, array &$found, string $editIf, string $verifyIf): array
    {
        foreach ($nodes as $key => $node) {
            if (! is_array($node)) {
                continue;
            }

            $description = $node['meta']['description'] ?? null;
            $if = $node['if'] ?? null;

            if ($description === self::EDIT_FORM_DESCRIPTION && in_array($if, [self::EDIT_FORM_ORIGINAL_IF, $editIf], true)) {
                $nodes[$key]['if'] = $editIf;
                $found['edit']++;
            } elseif ($description === self::VERIFY_SECTION_DESCRIPTION && in_array($if, [self::VERIFY_SECTION_ORIGINAL_IF, $verifyIf], true)) {
                $nodes[$key]['if'] = $verifyIf;
                $found['verify']++;
            }

            if (isset($node['children']) && is_array($node['children'])) {
                $nodes[$key]['children'] = $this->rewriteNodes($node['children'], $found, $editIf, $verifyIf);
            }
        }

        return $nodes;
    }

    private function editFormIf(): string
    {
        return '{{_local?.isPasswordVerified || user?.data?.'.self::RESOURCE_FIELD.' === false}}';
    }

    private function verifySectionIf(): string
    {
        return '{{!_local?.isPasswordVerified && user?.data?.'.self::RESOURCE_FIELD.' !== false}}';
    }
}
