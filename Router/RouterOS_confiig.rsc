:do {

    ################################
    # INTERFACE IP ADDRESSES
    ################################

    /ip address
    add address=192.168.10.1/24 interface=ether2 comment="LAN"
    add address=10.0.0.2/24 interface=ether1 comment="WAN"

    ################################
    # DEFAULT ROUTE (INTERNET)
    ################################

    /ip route
    add dst-address=0.0.0.0/0 gateway=10.0.0.1 comment="Default Internet Route"

    ################################
    # NAT MASQUERADE
    ################################

    /ip firewall nat
    add chain=srcnat out-interface=ether1 action=masquerade comment="NAT LAN to WAN"

    ################################
    # FIREWALL FILTER RULES
    ################################

    /ip firewall filter

    # --- INPUT CHAIN ---
    add chain=input connection-state=established,related action=accept comment="Allow established/related input"
    add chain=input connection-state=invalid action=drop comment="Drop invalid input"
    add chain=input in-interface=ether2 action=accept comment="Allow LAN management"
    add chain=input action=drop comment="Drop all other input"

    # --- FORWARD CHAIN ---
    /ip firewall filter
    add chain=forward connection-state=established,related action=accept comment="Allow replies"
    add chain=forward connection-state=invalid action=drop
    add chain=forward connection-nat-state=dstnat action=accept comment="Allow port forwards"
    add chain=forward in-interface=ether2 out-interface=ether1 action=accept comment="LAN to internet"
    add chain=forward action=drop comment="Drop everything else"
    
    ################################
    # FIREWALL DNAT
    ################################
    
    /ip firewall nat
add chain=dstnat in-interface=ether1 protocol=tcp dst-port=80 \
    action=dst-nat to-addresses=192.168.10.100 to-ports=80

} on-error={
    :log error "Setup script failed — check syntax or existing config"
}