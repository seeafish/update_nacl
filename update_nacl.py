import socket
import boto3

def _delete_nacl(acl_id):
    ec2 = boto3.client("ec2")

    response = ec2.describe_network_acls(
        NetworkAclIds=[acl_id]
    )

    for entry in response["NetworkAcls"][0]["Entries"]:
        if entry["Egress"] and entry["RuleAction"] == "allow":
            ec2.delete_network_acl_entry(
                Egress=True,
                NetworkAclId=acl_id,
                RuleNumber=entry["RuleNumber"]
            )

def get_ips():
    repo_urls = ["pypi.python.org", "rubygems.org"]
    ip_addresses = dict()
    for repo in repo_urls:
        ip_addresses[repo] = []
        for i in range(0, 5):       # TODO: Run this as many times as required
            ip = socket.gethostbyname(repo) + "/32"
            if ip not in ip_addresses[repo]:
                ip_addresses[repo].append(ip)
    return ip_addresses

def update_nacl(ip_addresses, rule_number, acl_id):
    _delete_nacl(acl_id)

    ec2 = boto3.resource("ec2")
    network_acl = ec2.NetworkAcl(acl_id)

    network_acl.create_entry(
        CidrBlock="0.0.0.0/0",
        DryRun=False,
        Egress=True,
        Protocol="-1",
        RuleAction="allow",
        RuleNumber=rule_number
    )

    for repo, ips in ip_addresses.items():
        for ip in ips:
            rule_number += 100
            network_acl.create_entry(
                CidrBlock=ip,
                DryRun=False,
                Egress=True,
                PortRange={
                    "From": 80,
                    "To": 443
                },
                Protocol="6",
                RuleAction="allow",
                RuleNumber=rule_number
            )

if __name__ == "__main__":
    update_nacl(get_ips(), 100, "acl-c010f4a6") # TODO: Remove static reference
