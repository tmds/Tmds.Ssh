namespace Tmds.Ssh;

sealed class TrustedHostKeys
{
    private List<SshKeyData>? TrustedKeys { get; set; }
    private List<SshKeyData>? TrustedPatternMatchedKeys { get; set; }
    private List<SshKeyData>? CAKeys { get; set; }
    private List<SshKeyData>? RevokedKeys { get; set; }

    public void AddTrustedKey(SshKeyData key, bool isPatternMatch)
    {
        if (isPatternMatch)
        {
            TrustedPatternMatchedKeys ??= new List<SshKeyData>();
            TrustedPatternMatchedKeys.Add(key);
        }
        else
        {
            TrustedKeys ??= new List<SshKeyData>();
            TrustedKeys.Add(key);
        }
    }

    public void AddCAKey(SshKeyData key)
    {
        CAKeys ??= new List<SshKeyData>();
        CAKeys.Add(key);
    }

    public void AddRevokedKey(SshKeyData key)
    {
        RevokedKeys ??= new List<SshKeyData>();
        RevokedKeys.Add(key);
    }

    public KnownHostResult IsTrusted(PublicKey hostKey, PublicKey? caKey)
    {
        if (RevokedKeys is not null)
        {
            if (caKey is not null && RevokedKeys.Contains(caKey.SshKeyData))
            {
                return KnownHostResult.Revoked;
            }
            if (RevokedKeys.Contains(hostKey.SshKeyData))
            {
                return KnownHostResult.Revoked;
            }
        }

        if (caKey is not null && CAKeys is not null)
        {
            if (CAKeys.Contains(caKey.SshKeyData))
            {
                return KnownHostResult.Trusted;
            }
        }

        bool anyTrusted = false;
        if (TrustedKeys is not null)
        {
            if (TrustedKeys.Contains(hostKey.SshKeyData))
            {
                return KnownHostResult.Trusted;
            }
            anyTrusted = TrustedKeys.Count > 0;
        }

        if (TrustedPatternMatchedKeys is not null)
        {
            if (TrustedPatternMatchedKeys.Contains(hostKey.SshKeyData))
            {
                return KnownHostResult.Trusted;
            }
        }

        return anyTrusted ? KnownHostResult.Changed : KnownHostResult.Unknown;
    }

    public void SortAlgorithms(List<Name> hostKeyAlgorithms)
    {
        int sortedIdx = 0;
        if (CAKeys is not null)
        {
            SortCAAlgorithmsFirst(hostKeyAlgorithms, ref sortedIdx);
        }

        if (TrustedKeys is null || TrustedKeys.Count == 0)
        {
            return;
        }

        if (TrustedKeys.Count == 1)
        {
            SshKeyData hostKey = TrustedKeys[0];
            Name keyType = hostKey.Type;
            ReadOnlySpan<Name> preferredAlgorithms = AlgorithmNames.GetHostKeyAlgorithmsForKnownHostKeyType(ref keyType);
            Sort(hostKeyAlgorithms, preferredAlgorithms, ref sortedIdx);
        }
        else
        {
            OrderedSet<Name> keyAlgorithms = new();
            // Reverse the order based on the assumption that the last key is the most recent (and therefore preferred).
            for (int i = TrustedKeys.Count - 1; i >= 0; i--)
            {
                Name keyType = TrustedKeys[i].Type;
                foreach (var algorithm in AlgorithmNames.GetHostKeyAlgorithmsForKnownHostKeyType(ref keyType))
                {
                    keyAlgorithms.Add(algorithm);
                }
            }
            ReadOnlySpan<Name> preferredAlgorithms = keyAlgorithms.OrderedItems;
            Sort(hostKeyAlgorithms, preferredAlgorithms, ref sortedIdx);
        }

        static void SortCAAlgorithmsFirst(List<Name> algorithms, ref int sortedIdx)
        {
            for (int i = 0; i < algorithms.Count; i++)
            {
                bool isCertAlgorithm = algorithms[i].EndsWith(AlgorithmNames.CertSuffix);
                if (isCertAlgorithm)
                {
                    if (sortedIdx != i)
                    {
                        (algorithms[sortedIdx], algorithms[i]) = (algorithms[i], algorithms[sortedIdx]);
                    }
                    sortedIdx++;
                }
            }
        }

        static void Sort(List<Name> algorithms, ReadOnlySpan<Name> preferredAlgorithms, ref int sortedIdx)
        {
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