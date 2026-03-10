<?php

declare(strict_types=1);

namespace ISWordPress\Sniffs\Security;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Flags use of the |raw filter in Twig templates.
 *
 * |raw disables Twig's autoescaping entirely for the output expression.
 * This is legitimate in some cases (e.g. output already sanitized via
 * wp_kses_post), but should always be a conscious, documented decision.
 *
 * Severity: warning — flags for review rather than hard blocking.
 *
 * To suppress a legitimate use, add a Twig comment on the preceding line:
 *   {# phpcs:ignore ISWordPress.Security.TwigRawFilter -- reason here #}
 *   {{ content | raw }}
 *
 * NOTE: PHPCS does not natively tokenize Twig. This sniff operates via
 * regex on raw file content, which is less precise than AST-based rules.
 * It scans .twig files only and ignores lines inside Twig comments.
 */
class TwigRawFilterSniff implements Sniff
{
    /**
     * Regex to match |raw usage in a Twig expression.
     * Matches: | raw, |raw, | raw }} etc.
     */
    private const RAW_PATTERN = '/\|\s*raw\b/';

    /**
     * Regex to detect a phpcs:ignore directive in a Twig comment.
     */
    private const IGNORE_PATTERN = '/\{#.*phpcs:ignore.*#\}/i';

    public function register(): array
    {
        // T_INLINE_HTML is how PHPCS sees raw non-PHP content.
        // For .twig files processed as HTML/text, this covers the file.
        return [ T_INLINE_HTML, T_OPEN_TAG ];
    }

    public function process( File $phpcsFile, $stackPtr ): void
    {
        // Only run on .twig files.
        if ( ! str_ends_with( $phpcsFile->getFilename(), '.twig' ) ) {
            return;
        }

        // We process the whole file once on the first token only,
        // to avoid firing once per token.
        if ( $stackPtr !== 0 ) {
            return;
        }

        $lines = explode( "\n", $phpcsFile->getTokensAsString( 0, count( $phpcsFile->getTokens() ) ) );

        foreach ( $lines as $lineIndex => $line ) {
            $lineNumber = $lineIndex + 1;

            // Skip lines that are themselves Twig comments.
            if ( preg_match( '/^\s*\{#/', $line ) ) {
                continue;
            }

            // Skip lines inside a Twig block comment (multi-line {# ... #}).
            // Simple heuristic: if the line doesn't contain |raw, skip regardless.
            if ( ! preg_match( self::RAW_PATTERN, $line ) ) {
                continue;
            }

            // Check if the immediately preceding line has a phpcs:ignore directive.
            if ( $lineIndex > 0 && preg_match( self::IGNORE_PATTERN, $lines[ $lineIndex - 1 ] ) ) {
                continue;
            }

            $phpcsFile->addWarning(
                '|raw filter suppresses Twig autoescaping. Ensure output is trusted or already sanitized (e.g. via wp_kses_post). To suppress this warning, add on the preceding line: {# phpcs:ignore ISWordPress.Security.TwigRawFilter -- reason #}',
                0, // Line/token targeting is limited outside PHP tokenization; PHPCS will report file-level.
                'RawFilterFound'
            );
        }
    }
}
