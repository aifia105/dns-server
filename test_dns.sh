#!/bin/bash

# Test script for DNS server

echo "=== Testing DNS Server ==="
echo ""

# Test UDP server 
echo "1. Testing UDP server (port 8080) with dig:"
dig @localhost -p 8080 google.com A
echo ""

# Test TCP server 
echo "2. Testing TCP server (port 8081) with dig:"
dig @localhost -p 8081 +tcp google.com A
echo ""

dig @localhost -p 8080 google.com A


dig @localhost -p 8080 github.com A


dig @localhost -p 8080 thisdomaindoesnotexist12345.com A

echo "=== Tests Complete ==="
