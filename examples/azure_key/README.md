# Azure Key Vault

This example shows how to authenticate with a private key that is stored in an Azure Key Vault without having to export the key to the local filesystem.

This example can be run in two different modes:
- `print_pub_key` - prints the public key string of the requested key
- `ssh` - runs the command over SSH using the private key specified

## Requirements

This example can use the following Azure Key Types:
- RSA [2048|3072|4096]
- EC P-[256|384|521]

The `EC P-256K` is not supported by SSH and ED25516 keys are not currently supported in Azure Key Vault so cannot be used in this example.

The client must have the ability to perform the following `dataActions` on the key:
- Microsoft.KeyVault/vaults/keys/read
- Microsoft.KeyVault/vaults/keys/sign/action

You can either create a custom role with these actions or use a builtin role with these actions present like `Key Vault Crypto User`.

## Examples

These examples use the Azure app secret env vars to authenticate with a registered app and its secret non-interactively. There are other ways to authenticate with Azure like a managed identity, Azure CLI creds, interactive OAuth, etc. See [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) for more details.

```bash
export AZURE_CLIENT_ID=...
export AZURE_TENANT_ID=...
export AZURE_CLIENT_SECRET=...

# Print pub key to add it into the authorized_keys file
dotnet run print_pub_key ${KEY_VAULT_NAME} ${KEY_NAME}

# Runs the whoami command for user on target
dotnet run ssh ${KEY_VAULT_NAME} ${KEY_NAME} user@target whoami
```
