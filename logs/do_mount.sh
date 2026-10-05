mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts
cp /data/local/tmp/cacerts_backup/* /apex/com.android.conscrypt/cacerts/
cp /data/local/tmp/b69ec367.0 /apex/com.android.conscrypt/cacerts/
chown root:root /apex/com.android.conscrypt/cacerts/*
chmod 644 /apex/com.android.conscrypt/cacerts/*
chcon -R u:object_r:system_security_cacerts_file:s0 /apex/com.android.conscrypt/cacerts
echo MOUNTED_COUNT=$(ls /apex/com.android.conscrypt/cacerts | wc -l)
echo HAS_MITM=$(ls /apex/com.android.conscrypt/cacerts | grep -c b69ec367)
