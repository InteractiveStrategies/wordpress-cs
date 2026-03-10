<?php

declare(strict_types=1);

namespace ISWordPress\Sniffs\Security;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Enforces that setcookie() and setrawcookie() always set Secure, HttpOnly,
 * and SameSite flags to prevent cookie-related vulnerabilities.
 *
 * Supports both call forms:
 *   - Options array (PHP 7.3+): setcookie('name', 'val', ['secure' => true, ...])
 *   - Positional args (legacy): setcookie('name', 'val', $exp, $path, $domain, $secure, $httponly)
 *     Note: SameSite cannot be set via positional args — the array form is required for it.
 */
class SecureCookieFlagsSniff implements Sniff
{
    /**
     * Functions to check.
     */
    private const COOKIE_FUNCTIONS = [ 'setcookie', 'setrawcookie' ];

    /**
     * Required keys when using the options array form.
     */
    private const REQUIRED_KEYS = [ 'secure', 'httponly', 'samesite' ];

    /**
     * Positional argument indices (0-based) for the legacy form.
     * setcookie(name, value, expires, path, domain, secure, httponly)
     *                                               [5]     [6]
     * SameSite is not available in positional form.
     */
    private const POSITIONAL_SECURE   = 5;
    private const POSITIONAL_HTTPONLY = 6;

    public function register(): array
    {
        return [ T_STRING ];
    }

    public function process( File $phpcsFile, $stackPtr ): void
    {
        $tokens = $phpcsFile->getTokens();
        $funcName = strtolower( $tokens[ $stackPtr ]['content'] );

        if ( ! in_array( $funcName, self::COOKIE_FUNCTIONS, true ) ) {
            return;
        }

        // Confirm it's a function call (next non-whitespace token is an open paren).
        $openParen = $phpcsFile->findNext( T_WHITESPACE, $stackPtr + 1, null, true );
        if ( $openParen === false || $tokens[ $openParen ]['code'] !== T_OPEN_PARENTHESIS ) {
            return;
        }

        $closeParen = $tokens[ $openParen ]['parenthesis_closer'];
        $args       = $this->getArgs( $phpcsFile, $openParen, $closeParen );

        if ( count( $args ) === 0 ) {
            return;
        }

        // Check if the third argument (index 2) is an array — options array form.
        if ( isset( $args[2] ) && $this->argIsArray( $phpcsFile, $args[2] ) ) {
            $this->checkArrayForm( $phpcsFile, $stackPtr, $args[2] );
        } else {
            $this->checkPositionalForm( $phpcsFile, $stackPtr, $args );
        }
    }

    /**
     * Check the options array form for required keys.
     */
    private function checkArrayForm( File $phpcsFile, int $stackPtr, array $argTokenRange ): void
    {
        $tokens      = $phpcsFile->getTokens();
        $foundKeys   = [];

        foreach ( $argTokenRange as $ptr ) {
            if ( $tokens[ $ptr ]['code'] === T_CONSTANT_ENCAPSED_STRING ) {
                $key = strtolower( trim( $tokens[ $ptr ]['content'], "'\"" ) );
                if ( in_array( $key, self::REQUIRED_KEYS, true ) ) {
                    $foundKeys[] = $key;
                }
            }
        }

        $missing = array_diff( self::REQUIRED_KEYS, $foundKeys );

        if ( ! empty( $missing ) ) {
            $phpcsFile->addError(
                '%s() options array is missing required security flag(s): %s. All cookies must set secure, httponly, and samesite unless the use case explicitly requires otherwise.',
                $stackPtr,
                'MissingSecurityFlags',
                [ $tokens[ $stackPtr ]['content'], implode( ', ', $missing ) ]
            );
        }
    }

    /**
     * Check the positional args form.
     * Positional form cannot set SameSite — flag that regardless.
     */
    private function checkPositionalForm( File $phpcsFile, int $stackPtr, array $args ): void
    {
        $tokens   = $phpcsFile->getTokens();
        $missing  = [];

        // Check $secure (arg index 5).
        if ( ! isset( $args[ self::POSITIONAL_SECURE ] ) ) {
            $missing[] = 'secure';
        }

        // Check $httponly (arg index 6).
        if ( ! isset( $args[ self::POSITIONAL_HTTPONLY ] ) ) {
            $missing[] = 'httponly';
        }

        // SameSite is never settable via positional args.
        $missing[] = 'samesite (not settable via positional args — use the options array form)';

        $phpcsFile->addError(
            '%s() called with positional arguments. Use the options array form (PHP 7.3+) to set secure, httponly, and samesite flags. Missing: %s.',
            $stackPtr,
            'UseOptionsArrayForm',
            [ $tokens[ $stackPtr ]['content'], implode( ', ', $missing ) ]
        );
    }

    /**
     * Split function call arguments into token ranges by comma separation at depth 0.
     * Returns an array of token pointer arrays, one per argument.
     */
    private function getArgs( File $phpcsFile, int $openParen, int $closeParen ): array
    {
        $tokens = $phpcsFile->getTokens();
        $args   = [];
        $depth  = 0;
        $current = [];

        for ( $i = $openParen + 1; $i < $closeParen; $i++ ) {
            $code = $tokens[ $i ]['code'];

            if ( in_array( $code, [ T_OPEN_PARENTHESIS, T_OPEN_SHORT_ARRAY, T_OPEN_SQUARE_BRACKET ], true ) ) {
                $depth++;
            } elseif ( in_array( $code, [ T_CLOSE_PARENTHESIS, T_CLOSE_SHORT_ARRAY, T_CLOSE_SQUARE_BRACKET ], true ) ) {
                $depth--;
            }

            if ( $code === T_COMMA && $depth === 0 ) {
                $args[] = $current;
                $current = [];
                continue;
            }

            $current[] = $i;
        }

        if ( ! empty( $current ) ) {
            $args[] = $current;
        }

        return $args;
    }

    /**
     * Check whether an argument token range contains an array expression.
     */
    private function argIsArray( File $phpcsFile, array $argTokens ): bool
    {
        $tokens = $phpcsFile->getTokens();

        foreach ( $argTokens as $ptr ) {
            $code = $tokens[ $ptr ]['code'];
            if ( $code === T_WHITESPACE ) {
                continue;
            }
            return in_array( $code, [ T_OPEN_SHORT_ARRAY, T_ARRAY ], true );
        }

        return false;
    }
}
