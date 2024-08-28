namespace Tmds.Ssh;

sealed class TrustedHostKeys
{
    private List<HostKey>? TrustedKeys { get; set; }
    private List<HostKey>? TrustedPatternMatchedKeys { get; set; }
    private List<HostKey>? RevokedKeys { get; set; }

    public void AddTrustedKey(HostKey key, bool isPatternMatch)
    {
        if (isPatternMatch)
        {
            TrustedPatternMatchedKeys ??= new List<HostKey>();
            TrustedPatternMatchedKeys.Add(key);
        }
        else
        {
            TrustedKeys ??= new List<HostKey>();
            TrustedKeys.Add(key);
        }
    }

    public void AddRevokedKey(HostKey key)
    {
        RevokedKeys ??= new List<HostKey>();
        RevokedKeys.Add(key);
    }

    public KnownHostResult IsTrusted(HostKey serverKey)
    {
        if (RevokedKeys is not null)
        {
            if (RevokedKeys.Contains(serverKey))
            {
                return KnownHostResult.Revoked;
            }
        }

        bool anyTrusted = false;
        if (TrustedKeys is not null)
        {
            if (TrustedKeys.Contains(serverKey))
            {
                return KnownHostResult.Trusted;
            }
            anyTrusted = TrustedKeys.Count > 0;
        }

        if (TrustedPatternMatchedKeys is not null)
        {
            if (TrustedPatternMatchedKeys.Contains(serverKey))
            {
                return KnownHostResult.Trusted;
            }
        }

        return anyTrusted ? KnownHostResult.Changed : KnownHostResult.Unknown;
    }

    public void SortAlgorithms(List<Name> algorithmNames)
    {
        if (TrustedKeys is null || TrustedKeys.Count == 0)
        {
            return;
        }

        if (TrustedKeys.Count == 1)
        {
            HostKey hostKey = TrustedKeys[0];
            Name keyType = hostKey.Type;
            ReadOnlySpan<Name> preferredAlgorithms = PublicKey.AlgorithmsForKeyType(ref keyType);
            Sort(algorithmNames, preferredAlgorithms);
        }
        else
        {
            OrderedSet<Name> keyAlgorithms = new();
            // Reverse the order based on the assumption that the last key is the most recent (and therefore preferred).
            for (int i = TrustedKeys.Count - 1; i >= 0; i--)
            {
                Name keyType = TrustedKeys[i].Type;
                foreach (var algorithm in PublicKey.AlgorithmsForKeyType(ref keyType))
                {
                    keyAlgorithms.Add(algorithm);
                }
            }
            ReadOnlySpan<Name> preferredAlgorithms = keyAlgorithms.OrderedItems;
            Sort(algorithmNames, preferredAlgorithms);
        }

        static void Sort(List<Name> algorithms, ReadOnlySpan<Name> preferredAlgorithms)
        {
            int sortedIdx = 0;
            foreach (var preferred in preferredAlgorithms)
            {
                int idx = algorithms.IndexOf(preferred, sortedIdx);
                if (idx != -1)
                {
                    if (sortedIdx != idx)
                    {
                        (algorithms[sortedIdx], algorithms[idx]) = (algorithms[idx], algorithms[sortedIdx]);
                    }
                    sortedIdx++;
                }
            }
        }
    }
}