#!/usr/bin/env /usr/bin/python3

import pkg_resources
pkg_resources.require('PyYAML>=5.1.1')

import sys
import yaml
import os
import base64

from functools import reduce
import operator

with open(sys.argv[1], "r") as stream:
    try:
        cfg = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print("Error parsing SecretChecksum input", file=sys.stderr)
        sys.exit(1)

yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str

def find(element, json):
    def _getitem(json, key):
        # Supports both list and dict
        try:
            key = int(key)
        except ValueError:
            pass
        return operator.getitem(json, key)
    return reduce(_getitem, element.split('.'), json)

def repr_str(dmp, data):
    if '\n' in data:
        return dmp.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')
    return dmp.org_represent_str(data)

yaml.add_representer(str, repr_str, Dumper=yaml.SafeDumper)

def yaml_stream():
    try:
        if len(sys.argv) > 2:
            f = open(sys.argv[2], "r")
        else:
            f = sys.stdin
        return yaml.safe_load_all(f)
    except yaml.YAMLError as exc:
        print("Error parsing YAML input\n\n%s\n\n" % exc, file=sys.stderr)
        sys.exit(1)

def match_secret(doc, secret):
    sec_namespaced_name = secret["namespacedName"]
    sec_apiversion = secret.get("apiVersion", 'v1')
    sec_kind = secret.get("kind", 'Secret')

    if doc["kind"] == sec_kind and doc["apiVersion"] == sec_apiversion:
        if [doc["metadata"]["namespace"], doc["metadata"]["name"]] == sec_namespaced_name.split('.'):
            return True
    return False

pod_match_list = [
    "DaemonSet",
    "Deployment",
    "StatefulSet",
    "ReplicaSet",
    "CronJob",
    "Job",
    "Pod",
]

def match_target_pod(doc, sec_namespaced_name, target_annotation):
    if doc["kind"] not in pod_match_list:
        return False
    (sec_namespace, _) = sec_namespaced_name.split('.')
    if doc["metadata"]["namespace"] == sec_namespace:
        pod = doc if doc["kind"] == "Pod" else doc["spec"]["template"]
        return target_annotation in pod["metadata"]["annotations"].keys()

def processSecret(secret):
    sec_namespaced_name = secret["namespacedName"]
    version_info_field = secret["versionInfoField"]
    target_annotation = secret["targetAnnotation"]

    version_info = None
    targets = []

    for doc in yaml_stream():
        if match_secret(doc, secret):
            try:
                version_info = find(version_info_field, doc)
            except Exception as exc:
                print("Target secret '%s' is missing versionInfo at '%s'\n\n%s\n\n" % (sec_namespaced_name, version_info_field, exc), file=sys.stderr)
        if match_target_pod(doc, sec_namespaced_name, target_annotation):
            targets.append(doc)
    if version_info is None:
        print("Couldn't find target secret %s" % sec_namespaced_name, file=sys.stderr)
    for target in targets:
        pod = target if target["kind"] == "Pod" else target["spec"]["template"]
        pod["metadata"]["annotations"][target_annotation] = version_info
    print(targets)

for secret in cfg["secrets"]:
    processSecret(secret)
