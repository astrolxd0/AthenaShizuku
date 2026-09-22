package com.kin.athena.service.shizuku;

interface IShizukuFirewallService {
    void destroy() = 16777114; // Destroy method with specific transaction code

    boolean enableFirewallChain() = 1;
    boolean disableFirewallChain() = 2;
    boolean isFirewallChainEnabled() = 3;

    boolean setPackageNetworking(String packageName, boolean enabled) = 4;
    boolean getPackageNetworking(String packageName) = 5;

    String executeCommand(String command) = 6;

    // Applies the same networking state to many packages in a single binder call.
    // Returns the number of packages that were updated successfully.
    int setPackagesNetworking(in List<String> packageNames, boolean enabled) = 7;
}
