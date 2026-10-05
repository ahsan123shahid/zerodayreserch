ZPID=$(ps -A -o PID,NAME | grep ' zygote64$' | awk '{print $1}' | tr -d '\r')
echo ZPID=$ZPID
echo BEFORE=$(nsenter --mount=/proc/$ZPID/ns/mnt ls /apex/com.android.conscrypt/cacerts 2>&1 | wc -l)
nsenter --mount=/proc/$ZPID/ns/mnt /system/bin/sh /data/local/tmp/do_mount.sh
echo AFTER=$(nsenter --mount=/proc/$ZPID/ns/mnt ls /apex/com.android.conscrypt/cacerts 2>&1 | wc -l)
echo MITM=$(nsenter --mount=/proc/$ZPID/ns/mnt ls /apex/com.android.conscrypt/cacerts 2>/dev/null | grep -c b69ec367)
