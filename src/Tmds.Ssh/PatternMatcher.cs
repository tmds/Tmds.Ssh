using System;

namespace Tmds.Ssh;

static class PatternMatcher
{
    // Handles '?', '*'. Does NOT handle '!' for negates.
    public static bool IsPatternMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> value)
        => MatchPattern(pattern, value);

    // Handles '?', '*', '!' for negates, and ',' for lists.
    public static bool IsPatternListMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> value)
    {
        int patternCount = pattern.Count(',') + 1;
        if (patternCount == 1)
        {
            bool isNegate = IsNegate(ref pattern);
            bool isMatch = MatchPattern(pattern, value);
            return isMatch && !isNegate;
        }
        else
        {
            bool hasNegates = pattern.Contains('!');
            Span<Range> destination = patternCount <= 32 ? stackalloc Range[patternCount] : new Range[patternCount];
            patternCount = pattern.Split(destination, ',', StringSplitOptions.RemoveEmptyEntries);
            destination = destination.Slice(0, patternCount);
            bool hasMatch = false;
            foreach (var range in destination)
            {
                ReadOnlySpan<char> childPattern = pattern[range];
                bool isNegate = hasNegates && IsNegate(ref childPattern);
                bool isMatch = MatchPattern(childPattern, value);
                if (isMatch)
                {
                    if (isNegate)
                    {
                        return false;
                    }

                    if (!hasNegates)
                    {
                        return true;
                    }
                    hasMatch = true;
                }
            }
            return hasMatch;
        }


    }

    public static bool IsNegate(ref ReadOnlySpan<char> pattern)
    {
        if (pattern.Length > 0 && pattern[0] == '!')
        {
            pattern = pattern.Slice(1);
            return true;
        }
        return false;
    }

    // Handles '?', '*'
    // Based on https://github.com/dotnet/runtime/blob/0806470e0181b0614b171f60fd59b5cebc4bf999/src/libraries/System.Private.CoreLib/src/System/IO/Enumeration/FileSystemName.cs#L141
    // The .NET Foundation licenses this under the MIT license.
    private static bool MatchPattern(ReadOnlySpan<char> expression, ReadOnlySpan<char> name)
    {
        // The idea behind the algorithm is pretty simple. We keep track of all possible locations
        // in the regular expression that are matching the name. When the name has been exhausted,
        // if one of the locations in the expression is also just exhausted, the name is in the
        // language defined by the regular expression.

        if (expression.Length == 0 || name.Length == 0)
            return false;

        if (expression[0] == '*')
        {
            // Just * matches everything
            if (expression.Length == 1)
                return true;

            ReadOnlySpan<char> expressionEnd = expression.Slice(1);

            // [MS - FSA] 2.1.4.4 Algorithm for Determining if a FileName Is in an Expression
            // https://msdn.microsoft.com/en-us/library/ff469270.aspx
            bool hasWildcards = expressionEnd.ContainsAny('*', '?');
            if (!hasWildcards)
            {
                // Handle the special case of a single starting *, which essentially means "ends with"

                // If the name doesn't have enough characters to match the remaining expression, it can't be a match.
                if (name.Length < expressionEnd.Length)
                    return false;

                // See if we end with the expression
                return name.EndsWith(expressionEnd, StringComparison.OrdinalIgnoreCase);
            }
        }

        int nameOffset = 0;
        int expressionOffset;

        int priorMatch;
        int currentMatch;
        int priorMatchCount;
        int matchCount = 1;

        char nameChar = '\0';
        char expressionChar;

        scoped Span<int> temp = default;
        Span<int> currentMatches = stackalloc int[16];
        Span<int> priorMatches = stackalloc int[16];
        priorMatches[0] = 0;

        int maxState = expression.Length * 2;
        int currentState;
        bool nameFinished = false;

        //  Walk through the name string, picking off characters.  We go one
        //  character beyond the end because some wild cards are able to match
        //  zero characters beyond the end of the string.
        //
        //  With each new name character we determine a new set of states that
        //  match the name so far.  We use two arrays that we swap back and forth
        //  for this purpose.  One array lists the possible expression states for
        //  all name characters up to but not including the current one, and other
        //  array is used to build up the list of states considering the current
        //  name character as well.  The arrays are then switched and the process
        //  repeated.
        //
        //  There is not a one-to-one correspondence between state number and
        //  offset into the expression. State numbering is not continuous.
        //  This allows a simple conversion between state number and expression
        //  offset.  Each character in the expression can represent one or two
        //  states.  * and DOS_STAR generate two states: expressionOffset * 2 and
        //  expressionOffset * 2 + 1.  All other expression characters can produce
        //  only a single state.  Thus expressionOffset = currentState / 2.

        while (!nameFinished)
        {
            if (nameOffset < name.Length)
            {
                // Not at the end of the name. Grab the current character and move the offset forward.
                nameChar = name[nameOffset++];
            }
            else
            {
                // At the end of the name. If the expression is exhausted, exit.
                if (priorMatches[matchCount - 1] == maxState)
                    break;

                nameFinished = true;
            }

            // Now, for each of the previous stored expression matches, see what
            // we can do with this name character.
            priorMatch = 0;
            currentMatch = 0;
            priorMatchCount = 0;

            while (priorMatch < matchCount)
            {
                // We have to carry on our expression analysis as far as possible for each
                // character of name, so we loop here until the expression stops matching.

                expressionOffset = (priorMatches[priorMatch++] + 1) / 2;

                while (expressionOffset < expression.Length)
                {
                    currentState = expressionOffset * 2;
                    expressionChar = expression[expressionOffset];

                    // We may be about to exhaust the local space for matches,
                    // so we have to reallocate if this is the case.
                    if (currentMatch >= currentMatches.Length - 2)
                    {
                        int newSize = currentMatches.Length * 2;
                        temp = new int[newSize];
                        currentMatches.CopyTo(temp);
                        currentMatches = temp;

                        temp = new int[newSize];
                        priorMatches.CopyTo(temp);
                        priorMatches = temp;
                    }

                    if (expressionChar == '*')
                    {
                        // '*' matches any character zero or more times.
                        goto MatchZeroOrMore;
                    }
                    else
                    {
                        // The remaining expression characters all match by consuming a character,
                        // so we need to force the expression and state forward.
                        currentState += 2;

                            if (expressionChar == '\\')
                            {
                                // Escape character, try to move the expression forward again and match literally.
                                if (++expressionOffset == expression.Length)
                                {
                                    currentMatches[currentMatch++] = maxState;
                                    goto ExpressionFinished;
                                }

                                currentState = expressionOffset * 2 + 2;
                                expressionChar = expression[expressionOffset];
                            }

                            // From this point on a name character is required to even
                            // continue, let alone make a match.
                            if (nameFinished) goto ExpressionFinished;

                            if (expressionChar == '?')
                            {
                                // If this expression was a '?' we can match it once.
                                currentMatches[currentMatch++] = currentState;
                            }
                            else if (char.ToUpperInvariant(expressionChar) == char.ToUpperInvariant(nameChar))
                            {
                                // Matched a non-wildcard character
                                currentMatches[currentMatch++] = currentState;
                            }

                            goto ExpressionFinished;
                    }

                MatchZeroOrMore:
                    currentMatches[currentMatch++] = currentState;
                // MatchZero:
                    currentMatches[currentMatch++] = currentState + 1;
                // NextExpressionCharacter:
                    if (++expressionOffset == expression.Length)
                        currentMatches[currentMatch++] = maxState;
                } // while (expressionOffset < expression.Length)

            ExpressionFinished:

                // Prevent duplication in the destination array.
                //
                // Each of the arrays is monotonically increasing and non-duplicating, thus we skip
                // over any source element in the source array if we just added the same element to
                // the destination array. This guarantees non-duplication in the destination array.

                if ((priorMatch < matchCount) && (priorMatchCount < currentMatch))
                {
                    while (priorMatchCount < currentMatch)
                    {
                        int previousLength = priorMatches.Length;
                        while ((priorMatch < previousLength) && (priorMatches[priorMatch] < currentMatches[priorMatchCount]))
                        {
                            priorMatch++;
                        }
                        priorMatchCount++;
                    }
                }
            } // while (sourceCount < matchesCount)

            // If we found no matches in the just finished iteration it's time to bail.
            if (currentMatch == 0)
                return false;

            // Swap the meaning the two arrays
            temp = priorMatches;
            priorMatches = currentMatches;
            currentMatches = temp;

            matchCount = currentMatch;
        } // while (!nameFinished)

        currentState = priorMatches[matchCount - 1];

        return currentState == maxState;
    }
}
