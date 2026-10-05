#!/system/bin/sh
echo "shell_ns=$(readlink /proc/self/ns/mnt)"
echo "--- shell cacerts:"
ls /apex/com.android.conscrypt/cacerts | wc -l
for name in com.instagram.android zygote64 com.android.chrome; do
  for p in $(ps -A -o PID,NAME | awk -v n="$name" '$2==n {print $1}'); do
    echo "pid=$p name=$name ns=$(readlink /proc/$p/ns/mnt)"
    echo "  count=$(ls /proc/$p/root/apex/com.android.conscrypt/cacerts 2>/dev/null | wc -l)"
    echo "  has_mitm=$(ls /proc/$p/root/apex/com.android.conscrypt/cacerts 2>/dev/null | grep -c b69ec367)"
    echo "  mountinfo: $(grep cacerts /proc/$p/mountinfo 2>/dev/null)"
  done
done
