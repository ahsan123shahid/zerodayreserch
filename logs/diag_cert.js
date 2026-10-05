Java.perform(function () {
    try {
        var File = Java.use('java.io.File');
        var dir = File.$new('/apex/com.android.conscrypt/cacerts');
        var list = dir.list();
        send('[certdir] exists=' + dir.exists() + ' canRead=' + dir.canRead() + ' count=' + (list ? list.length : 'null'));
        send('[certdir] has_b69ec367=' + (list ? list.toString().indexOf('b69ec367') >= 0 : false));
    } catch (e) {
        send('[certdir] err ' + e);
    }

    try {
        var File2 = Java.use('java.io.File');
        var f = File2.$new('/apex/com.android.conscrypt/cacerts/b69ec367.0');
        send('[certfile] exists=' + f.exists() + ' canRead=' + f.canRead() + ' len=' + f.length());
    } catch (e) {
        send('[certfile] err ' + e);
    }

    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        var CF = Java.use('java.security.cert.CertificateFactory');
        var cf = CF.getInstance('X.509');
        var fis = FileInputStream.$new('/apex/com.android.conscrypt/cacerts/b69ec367.0');
        var cert = cf.generateCertificate(fis);
        fis.close();
        send('[parse] ok subject=' + cert.getSubjectX500Principal().getName());
    } catch (e) {
        send('[parse] err ' + e);
    }

    try {
        var TMF = Java.use('javax.net.ssl.TrustManagerFactory');
        var tmf = TMF.getInstance(TMF.getDefaultAlgorithm());
        tmf.init(null);
        var tms = tmf.getTrustManagers();
        send('[tmf] count=' + tms.length + ' type=' + tms[0].getClass().getName());
    } catch (e) {
        send('[tmf] err ' + e);
    }

    try {
        var NSS = Java.use('android.security.net.config.NetworkSecurityConfig');
        send('[nsc] loaded ok');
    } catch (e) {
        send('[nsc] err ' + e);
    }

    try {
        var names = Java.enumerateLoadedClassesSync();
        var hit = [];
        for (var i = 0; i < names.length; i++) {
            if (/CertificatePinner|CertPinManager|CronetEngineBuilder|TrustManagerImpl|TrustedCertificateStore|DirectoryCertificateSource/i.test(names[i])) hit.push(names[i]);
        }
        send('[pinning-classes] ' + (hit.length ? hit.join(' | ') : 'NONE'));
    } catch (e) {
        send('[pinning-classes] err ' + e);
    }
});
