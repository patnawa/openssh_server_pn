namespace OpenSSHServerPNManager
{
    /// <summary>The permission policy for agent state and archives. Production always uses SYSTEM/Administrators only.</summary>
    internal static class AgentStorage
    {
        internal static string RootOverride;
        internal static string Root { get { return RootOverride ?? Ssh.ConfigDir; } }
        internal interface PermissionPolicy
        {
            void CreateFolder(string path);
            void RestrictFile(string path);
        }

        private sealed class AdministrativePermissions : PermissionPolicy
        {
            public void CreateFolder(string path) { Acl.CreatePrivateFolder(path); }
            public void RestrictFile(string path) { Acl.Restrict(path, null); }
        }

        // The test harness supplies a policy confined to its own scratch directory; there is no path-based production bypass.
        internal static PermissionPolicy Permissions = new AdministrativePermissions();
    }
}
