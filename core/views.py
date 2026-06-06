# =========================
# IMPORTS
# =========================

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponse

import shodan
import subprocess
import nmap
import requests


# =========================
# APIs
# =========================

SHODAN_API_KEY = "7jcsDsIrdg5SiXPUkXmc4POD30wXaZm5"

HUNTER_API_KEY = "42b50e6dcfdcb19a29838f8cd04731768a2b1a02"


# =========================
# LOGIN
# =========================

def login_view(request):

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user:

            login(request, user)

            return redirect("dashboard")

        return render(request, "login.html", {
            "error": "Invalid credentials"
        })

    return render(request, "login.html")


# =========================
# REGISTER
# =========================

def register_view(request):

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():

            return render(request, "register.html", {
                "error": "User already exists"
            })

        user = User.objects.create_user(
            username=username,
            password=password
        )

        user.save()

        return redirect("login")

    return render(request, "register.html")


# =========================
# DASHBOARD
# =========================

def dashboard(request):

    result = None
    ports = []
    usernames = []
    network_devices = []
    email_result = None
    error = None

    security_score = None
    security_level = None

    query = request.GET.get("query")
    search_type = request.GET.get("type")

    # ==================================================
    # IP SEARCH
    # ==================================================

    if query and search_type == "ip":

        try:

            api = shodan.Shodan(SHODAN_API_KEY)

            host = api.host(query)

            ports = host.get("ports", [])

            result = {

                "IP Address": host.get("ip_str"),
                "Organization": host.get("org"),
                "Operating System": host.get("os"),
                "Country": host.get("country_name"),
                "City": host.get("city"),
                "ISP": host.get("isp"),
                "Hostnames": host.get("hostnames"),

            }

            # =========================
            # SECURITY SCORE
            # =========================

            security_score = 100

            if len(ports) > 10:

                security_score -= 50

            elif len(ports) > 5:

                security_score -= 30

            elif len(ports) > 2:

                security_score -= 15

            if host.get("os"):

                security_score -= 10

            if security_score >= 70:

                security_level = "Secure"

            elif security_score >= 40:

                security_level = "Medium"

            else:

                security_level = "Dangerous"

        except Exception as e:

            error = str(e)

    # ==================================================
    # USERNAME SEARCH
    # ==================================================

    elif query and search_type == "username":

        try:

            command = f'sherlock {query} --print-found'

            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )

            output = process.stdout.splitlines()

            for line in output:

                if "http" in line:

                    usernames.append(line)

            if not usernames:

                error = "No username found"

        except Exception as e:

            error = str(e)

    # ==================================================
    # LOCAL NETWORK SCAN
    # ==================================================

    elif query and search_type == "localscan":

        try:

            scanner = nmap.PortScanner()

            scanner.scan(
                hosts=query,
                arguments='-sS -Pn -p 1-1024'
            )

            hosts_list = scanner.all_hosts()

            for host in hosts_list:

                device = {

                    "ip": host,
                    "hostname": scanner[host].hostname(),
                    "state": scanner[host].state(),
                    "open_ports": [],
                    "security_score": 100,
                    "security_level": "Secure"

                }

                for proto in scanner[host].all_protocols():

                    ports_list = sorted(
                        scanner[host][proto].keys()
                    )

                    for port in ports_list:

                        state = scanner[host][proto][port]["state"]

                        if state == "open":

                            device["open_ports"].append(port)

                            # =========================
                            # SECURITY SCORE
                            # =========================

                            if port in [21, 23, 135, 139, 445]:

                                device["security_score"] -= 20

                            else:

                                device["security_score"] -= 5

                # =========================
                # SECURITY LEVEL
                # =========================

                if device["security_score"] >= 70:

                    device["security_level"] = "Secure"

                elif device["security_score"] >= 40:

                    device["security_level"] = "Medium"

                else:

                    device["security_level"] = "Dangerous"

                network_devices.append(device)

        except Exception as e:

            error = str(e)

    # ==================================================
    # EMAIL LOOKUP WITH HUNTER.IO
    # ==================================================

    elif query and search_type == "email":

        try:

            url = (
                f"https://api.hunter.io/v2/email-verifier"
                f"?email={query}"
                f"&api_key={HUNTER_API_KEY}"
            )

            response = requests.get(url)

            data = response.json()

            email_data = data.get("data", {})

            email_result = {

                "Email": email_data.get("email"),
                "Result": email_data.get("result"),
                "Score": email_data.get("score"),
                "Status": email_data.get("status"),
                "Domain": email_data.get("domain"),
                "Disposable": email_data.get("disposable"),
                "Webmail": email_data.get("webmail"),
                "MX Records": email_data.get("mx_records"),
                "SMTP Server": email_data.get("smtp_server"),
                "SMTP Check": email_data.get("smtp_check"),
                "Accept All": email_data.get("accept_all"),
                "Block": email_data.get("block"),
                "Gibberish": email_data.get("gibberish")

            }

            # =========================
            # SECURITY SCORE
            # =========================

            security_score = 100

            if email_data.get("disposable"):

                security_score -= 40

            if not email_data.get("mx_records"):

                security_score -= 25

            if not email_data.get("smtp_check"):

                security_score -= 20

            if email_data.get("gibberish"):

                security_score -= 30

            if security_score >= 70:

                security_level = "Secure"

            elif security_score >= 40:

                security_level = "Medium"

            else:

                security_level = "Dangerous"

        except Exception as e:

            error = str(e)

    return render(request, "dashboard.html", {

        "result": result,
        "ports": ports,
        "usernames": usernames,
        "network_devices": network_devices,
        "email_result": email_result,
        "security_score": security_score,
        "security_level": security_level,
        "error": error

    })


# =========================
# DOWNLOAD RESULTS
# =========================

def download_results(request):

    query = request.GET.get("query", "")
    search_type = request.GET.get("type", "")

    content = ""

    # ==================================================
    # IP SEARCH
    # ==================================================

    if search_type == "ip":

        try:

            api = shodan.Shodan(SHODAN_API_KEY)

            host = api.host(query)

            ports = host.get("ports", [])

            content += "========== IP INFORMATION ==========\n\n"

            content += f"IP Address : {host.get('ip_str')}\n"
            content += f"Organization : {host.get('org')}\n"
            content += f"Operating System : {host.get('os')}\n"
            content += f"Country : {host.get('country_name')}\n"
            content += f"City : {host.get('city')}\n"
            content += f"ISP : {host.get('isp')}\n"

            content += "\n========== OPEN PORTS ==========\n\n"

            for port in ports:

                content += f"Port : {port}\n"

        except Exception as e:

            content += str(e)

    # ==================================================
    # USERNAME SEARCH
    # ==================================================

    elif search_type == "username":

        try:

            command = f'sherlock {query} --print-found'

            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )

            output = process.stdout.splitlines()

            content += "========== USERNAME RESULTS ==========\n\n"

            for line in output:

                if "http" in line:

                    content += line + "\n"

        except Exception as e:

            content += str(e)

    # ==================================================
    # EMAIL SEARCH
    # ==================================================

    elif search_type == "email":

        try:

            url = (
                f"https://api.hunter.io/v2/email-verifier"
                f"?email={query}"
                f"&api_key={HUNTER_API_KEY}"
            )

            response = requests.get(url)

            data = response.json()

            email_data = data.get("data", {})

            content += "========== EMAIL RESULTS ==========\n\n"

            for key, value in email_data.items():

                content += f"{key} : {value}\n"

        except Exception as e:

            content += str(e)

    # ==================================================
    # LOCAL NETWORK SCAN
    # ==================================================

    elif search_type == "localscan":

        try:

            scanner = nmap.PortScanner()

            scanner.scan(
                hosts=query,
                arguments='-sS -Pn -p 1-1024'
            )

            hosts_list = scanner.all_hosts()

            content += "========== NETWORK DEVICES ==========\n\n"

            for host in hosts_list:

                content += f"\nIP : {host}\n"

                hostname = scanner[host].hostname()

                content += f"Hostname : {hostname}\n"

                content += "Open Ports :\n"

                for proto in scanner[host].all_protocols():

                    ports_list = sorted(
                        scanner[host][proto].keys()
                    )

                    for port in ports_list:

                        state = scanner[host][proto][port]["state"]

                        if state == "open":

                            content += f" - {port}\n"

        except Exception as e:

            content += str(e)

    # ==================================================
    # GENERATE FILE
    # ==================================================

    response = HttpResponse(
        content,
        content_type="text/plain"
    )

    response[
        "Content-Disposition"
    ] = f'attachment; filename="{search_type}_results.txt"'

    return response


# =========================
# LOGOUT
# =========================

def logout_view(request):

    logout(request)

    return redirect("login")