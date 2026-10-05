Java.perform(function () {
    console.log("[*] Universal JCA Bridge Initialized...");

    // Method 1: Hooking standard Network Security Config
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function () {
            return true;
        };
        console.log("[+] Universal Hook: Cleartext permitted forced.");
    } catch (e) { }

    // Method 2: Dynamic Certificate Factory Spoofing
    try {
        var CertificateFactory = Java.use('java.security.cert.CertificateFactory');
        CertificateFactory.getInstance.overload('java.lang.String').implementation = function (type) {
            console.log("[*] Intercepted CertFactory Instance creation for: " + type);
            return this.getInstance(type);
        };
    } catch (e) { }
});
