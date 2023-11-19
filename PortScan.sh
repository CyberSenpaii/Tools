export ip=172.16.1.13; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
