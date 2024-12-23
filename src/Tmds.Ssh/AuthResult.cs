// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

enum AuthResult
{
    // No credential
    None,
    // We didn't try to use the credential
    Skipped,
    // Skipped because the method is not allowed
    SkippedMethodNotAllowed,
    // Tried but failed
    Failure,
    // Failed and method tried is not allowed
    FailureMethodNotAllowed,
    Success,
    Partial,
}