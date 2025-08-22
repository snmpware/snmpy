#!/bin/bash
# Esempi di utilizzo della CLI di AdvancedSnmp

echo "Esempi CLI AdvancedSnmp"
echo "======================"
echo ""

# Variabili di configurazione
UPS_IP="192.168.1.100"
ROUTER_IP="192.168.1.1"
COMMUNITY="public"
PRIVATE_COMMUNITY="private"

echo "NOTA: Modifica le variabili IP nel file per i tuoi dispositivi"
echo "UPS_IP=$UPS_IP"
echo "ROUTER_IP=$ROUTER_IP"
echo ""

echo "=== Test Connessione ==="
echo "Test connessione SNMP di base:"
echo "python snmpy.py --ip $UPS_IP --test"
echo ""

echo "Test con community personalizzata:"
echo "python snmpy.py --ip $UPS_IP --community $COMMUNITY --test"
echo ""

echo "Test con timeout personalizzato:"
echo "python snmpy.py --ip $UPS_IP --test --timeout 5"
echo ""

echo "=== SNMPv1 ==="
echo "Monitoraggio UPS con SNMPv1:"
echo "python snmpy.py --ip $UPS_IP --version 1 --community $COMMUNITY"
echo ""

echo "=== SNMPv2c ==="
echo "Monitoraggio UPS con SNMPv2c (default):"
echo "python snmpy.py --ip $UPS_IP --version 2 --community $COMMUNITY"
echo ""

echo "Monitoraggio con intervallo personalizzato (ogni 10 secondi):"
echo "python snmpy.py --ip $UPS_IP --interval 10"
echo ""

echo "Monitoraggio limitato nel tempo (5 minuti):"
echo "python snmpy.py --ip $UPS_IP --duration 300"
echo ""

echo "=== SNMPv3 noAuthNoPriv ==="
echo "SNMPv3 senza autenticazione:"
echo "python snmpy.py --ip $UPS_IP --version 3 --v3-user public"
echo ""

echo "=== SNMPv3 authNoPriv ==="
echo "SNMPv3 con autenticazione MD5:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user authuser \\"
echo "    --v3-auth-protocol MD5 \\"
echo "    --v3-auth-password myauthpassword"
echo ""

echo "SNMPv3 con autenticazione SHA:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user authuser \\"
echo "    --v3-auth-protocol SHA \\"
echo "    --v3-auth-password myauthpassword"
echo ""

echo "SNMPv3 con autenticazione SHA256:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user authuser \\"
echo "    --v3-auth-protocol SHA256 \\"
echo "    --v3-auth-password myauthpassword"
echo ""

echo "=== SNMPv3 authPriv ==="
echo "SNMPv3 con autenticazione SHA e privacy DES:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user secureuser \\"
echo "    --v3-auth-protocol SHA \\"
echo "    --v3-auth-password myauthpassword \\"
echo "    --v3-priv-protocol DES \\"
echo "    --v3-priv-password myprivpassword"
echo ""

echo "SNMPv3 con autenticazione SHA256 e privacy AES128:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user secureuser \\"
echo "    --v3-auth-protocol SHA256 \\"
echo "    --v3-auth-password myauthpassword123 \\"
echo "    --v3-priv-protocol AES128 \\"
echo "    --v3-priv-password myprivpassword123"
echo ""

echo "SNMPv3 configurazione massima sicurezza:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user supersecureuser \\"
echo "    --v3-auth-protocol SHA512 \\"
echo "    --v3-auth-password very_secure_auth_password_2024 \\"
echo "    --v3-priv-protocol AES256 \\"
echo "    --v3-priv-password very_secure_priv_password_2024"
echo ""

echo "=== Discovery e Walk ==="
echo "SNMP Walk per scoprire OID disponibili:"
echo "python snmpy.py --ip $UPS_IP --walk"
echo ""

echo "Walk con SNMPv3:"
echo "python snmpy.py --ip $UPS_IP --version 3 \\"
echo "    --v3-user walkuser \\"
echo "    --v3-auth-protocol SHA \\"
echo "    --v3-auth-password walkpassword \\"
echo "    --walk"
echo ""

echo "=== Debug e Logging ==="
echo "Monitoraggio con debug abilitato:"
echo "python snmpy.py --ip $UPS_IP --debug"
echo ""

echo "Monitoraggio con logging dettagliato:"
echo "python snmpy.py --ip $UPS_IP --debug --interval 5 > ups_log.txt 2>&1"
echo ""

echo "=== Esempi di Script Automatizzati ==="
echo ""

echo "Script per test automatico di connessione:"
cat << 'EOF'
#!/bin/bash
# test_ups_connection.sh
UPS_IP="192.168.1.100"

echo "Test connessione UPS $UPS_IP..."

# Test SNMPv2c
if python snmpy.py --ip $UPS_IP --test --community public; then
    echo "✓ SNMPv2c funziona"
else
    echo "✗ SNMPv2c fallito"
fi

# Test SNMPv3 noAuth
if python snmpy.py --ip $UPS_IP --version 3 --v3-user public --test; then
    echo "✓ SNMPv3 noAuth funziona"
else
    echo "✗ SNMPv3 noAuth fallito"
fi
EOF
echo ""

echo "Script per monitoraggio continuo con log:"
cat << 'EOF'
#!/bin/bash
# monitor_ups_continuous.sh
UPS_IP="192.168.1.100"
LOG_FILE="ups_monitor_$(date +%Y%m%d_%H%M%S).log"

echo "Avvio monitoraggio UPS $UPS_IP..."
echo "Log salvato in: $LOG_FILE"

python snmpy.py --ip $UPS_IP \
    --community public \
    --interval 30 \
    --debug 2>&1 | tee $LOG_FILE
EOF
echo ""

echo "Script per backup configurazione UPS (se supportato):"
cat << 'EOF'
#!/bin/bash
# backup_ups_config.sh
UPS_IP="192.168.1.100"
BACKUP_DIR="ups_backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

echo "Backup configurazione UPS $UPS_IP..."

# Walk completo per backup
python snmpy.py --ip $UPS_IP --walk > "$BACKUP_DIR/ups_${UPS_IP}_${DATE}.txt"

echo "Backup salvato in: $BACKUP_DIR/ups_${UPS_IP}_${DATE}.txt"
EOF
echo ""

echo "=== Esempi Multi-UPS ==="
echo ""

echo "Script per monitoraggio multipli UPS:"
cat << 'EOF'
#!/bin/bash
# monitor_multiple_ups.sh

UPS_LIST=(
    "192.168.1.100:public:UPS-DC1"
    "192.168.1.101:public:UPS-DC2"
    "192.168.1.102:public:UPS-Office"
)

echo "Monitoraggio Multi-UPS"
echo "====================="

for ups_config in "${UPS_LIST[@]}"; do
    IFS=':' read -r ip community name <<< "$ups_config"
    
    echo ""
    echo "=== $name ($ip) ==="
    
    if python snmpy.py --ip $ip --community $community --test; then
        echo "✓ $name online - avvio monitoraggio in background"
        python snmpy.py --ip $ip --community $community --duration 60 > "${name}_log.txt" 2>&1 &
    else
        echo "✗ $name offline"
    fi
done

echo ""
echo "Tutti i monitoraggi avviati in background"
echo "Usa 'jobs' per vedere i processi attivi"
echo "Usa 'kill %n' per fermare un processo specifico"
EOF
echo ""

echo "=== Monitoraggio con Notifiche ==="
echo ""

echo "Script con notifiche email (richiede mailutils):"
cat << 'EOF'
#!/bin/bash
# ups_monitor_with_alerts.sh
UPS_IP="192.168.1.100"
EMAIL="admin@example.com"
ALERT_LOAD_THRESHOLD=80
ALERT_BATTERY_THRESHOLD=20

check_ups_status() {
    # Estrai info UPS (questo è un esempio semplificato)
    # In realtà dovresti parsare l'output JSON o usare l'API Python
    
    python snmpy.py --ip $UPS_IP --duration 5 > temp_ups_status.txt 2>&1
    
    # Simula controllo soglie (logica semplificata)
    if grep -q "Carico.*9[0-9]%" temp_ups_status.txt; then
        echo "ALERT: Carico UPS alto" | mail -s "UPS Alert: High Load" $EMAIL
    fi
    
    if grep -q "Batteria.*1[0-9]%" temp_ups_status.txt; then
        echo "ALERT: Batteria UPS bassa" | mail -s "UPS Alert: Low Battery" $EMAIL
    fi
    
    rm -f temp_ups_status.txt
}

# Controllo ogni 5 minuti
while true; do
    check_ups_status
    sleep 300
done
EOF
echo ""

echo "=== Comando per Esecuzione Rapida ==="
echo ""
echo "Per testare rapidamente un UPS:"
echo "python snmpy.py --ip 192.168.1.100 --test && python snmpy.py --ip 192.168.1.100 --duration 30"
echo ""

echo "Per monitoraggio continuo semplice:"
echo "python snmpy.py --ip 192.168.1.100 --interval 10"
echo ""

echo "Per debugging completo:"
echo "python snmpy.py --ip 192.168.1.100 --debug --walk | tee debug_output.txt"
echo ""

echo "=== Note Finali ==="
echo "1. Sostituisci sempre gli IP con quelli dei tuoi dispositivi"
echo "2. Verifica che le community string siano corrette"
echo "3. Per SNMPv3, configura prima gli utenti sui dispositivi"
echo "4. Usa --debug per troubleshooting"
echo "5. I log possono diventare grandi, usa logrotate in produzione"
echo ""
