setImmediate(function () {
    Java.perform(function () {
        var patterns = /pinner|pinning|certpin|certificatepinner|sslcontext|trustmanager|cronet|conscrypt/i;
        var hits = [];
        try {
            var all = Java.enumerateLoadedClassesSync();
            for (var i = 0; i < all.length; i++) {
                if (patterns.test(all[i])) hits.push(all[i]);
            }
        } catch (e) {
            send("[err] enum " + e);
        }
        send("[classes] total=" + hits.length);
        send(hits.join("\n"));

        try {
            var cl = Java.enumerateClassLoadersSync();
            send("[loaders] " + cl.length);
            for (var j = 0; j < cl.length; j++) {
                send("  loader: " + cl[j].toString());
            }
        } catch (e) {
            send("[err] loaders " + e);
        }
    });
});
