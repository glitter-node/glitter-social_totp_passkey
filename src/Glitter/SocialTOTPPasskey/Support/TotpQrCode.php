<?php

namespace Glitter\SocialTOTPPasskey\Support;

use Glitter\SocialTotpPasskey\Vendor\BaconQrCode\Renderer\Image\SvgImageBackEnd;
use Glitter\SocialTotpPasskey\Vendor\BaconQrCode\Renderer\ImageRenderer;
use Glitter\SocialTotpPasskey\Vendor\BaconQrCode\Renderer\RendererStyle\RendererStyle;
use Glitter\SocialTotpPasskey\Vendor\BaconQrCode\Writer;

/**
 * Local SVG QR renderer boundary for TOTP enrollment.
 *
 * Rendering is fail-closed: invalid or unavailable QR output returns null so
 * the enrollment flow can retain its manual-key fallback without exposing the
 * secret to an external QR service.
 */
final class TotpQrCode
{
    private const SIZE = 256;

    private const MAX_SVG_BYTES = 262144;

    /**
     * @var array<string, true>
     */
    private const ALLOWED_ELEMENTS = [
        'svg' => true,
        'rect' => true,
        'g' => true,
        'path' => true,
        'defs' => true,
        'radialGradient' => true,
        'linearGradient' => true,
        'stop' => true,
    ];

    public static function toDataUri(string $otpauthUri): ?string
    {
        if ($otpauthUri === '') {
            return null;
        }

        try {
            $svg = (new Writer(new ImageRenderer(
                new RendererStyle(self::SIZE),
                new SvgImageBackEnd(),
            )))->writeString($otpauthUri);

            if (! self::isSafeSvg($svg)) {
                return null;
            }

            return 'data:image/svg+xml;base64,'.base64_encode($svg);
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::warning('TOTP QR rendering failed', [
                'exception_class' => get_class($e),
                'error_code' => 'totp_qr_render_failed',
            ]);
            return null;
        }
    }

    private static function isSafeSvg(string $svg): bool
    {
        if ($svg === '' || strlen($svg) > self::MAX_SVG_BYTES) {
            return false;
        }

        if (! class_exists(\DOMDocument::class)) {
            return false;
        }

        $document = new \DOMDocument();
        $document->resolveExternals = false;
        $document->substituteEntities = false;

        $loaded = @$document->loadXML($svg, LIBXML_NONET | LIBXML_NOBLANKS);
        $root = $document->documentElement;
        if ($loaded !== true
            || ! $root instanceof \DOMElement
            || $root->tagName !== 'svg'
            || $root->namespaceURI !== 'http://www.w3.org/2000/svg'
            || $document->doctype !== null
        ) {
            return false;
        }

        foreach ($document->getElementsByTagName('*') as $element) {
            if (! $element instanceof \DOMElement
                || ! isset(self::ALLOWED_ELEMENTS[$element->tagName])) {
                return false;
            }

            foreach ($element->attributes as $attribute) {
                $name = strtolower($attribute->nodeName);
                $value = strtolower(trim($attribute->nodeValue));
                if (str_starts_with($name, 'on')
                    || preg_match('/(?:javascript:|https?:|\/\/|data:)/i', $value) === 1
                ) {
                    return false;
                }
            }
        }

        return true;
    }
}
