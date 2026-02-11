import json
import time
import logging
import argparse
import subprocess
import os
import yaml
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from zapv2 import ZAPv2
from typing import Optional, Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def log_error(message: str):
    print(f"::error::{message}")


def log_warning(message: str):
    print(f"::warning::{message}")


def log_notice(message: str):
    print(f"::notice::{message}")


def load_cwe_scanners(config_file: str) -> Dict[str, List[int]]:
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            if config and 'cwe_scanners' in config:
                logger.info(f"Loaded CWE scanners from {config_file}")
                return config['cwe_scanners']
            else:
                log_error(f"Invalid CWE scanner configuration in {config_file}")
                raise SystemExit(1)
    except FileNotFoundError:
        log_error(f"CWE scanner configuration file not found: {config_file}")
        raise SystemExit(1)
    except Exception as e:
        log_error(f"Failed to load CWE scanners from {config_file}: {e}")
        raise SystemExit(1)

INPUT_VECTORS = {"query": 1, "body": 2, "path": 4, "header": 8, "cookie": 16}
DEFAULT_INPUT_VECTOR = 31
DEFAULT_RPC = 5

@dataclass
class Endpoint:
    cwe: str
    method: str
    path: str
    input_vectors: int
    rule_id: str
    rule_name: str
    description: str
    risk_level: str
    matched_url: Optional[str] = None
    postdata: Optional[str] = None
    scan_id: Optional[str] = None
    scan_error: Optional[str] = None
    
    @property
    def is_scannable(self) -> bool:
        return self.matched_url is not None


@dataclass
class ScanResults:
    confirmed: List[Endpoint]
    unconfirmed: List[Endpoint]
    not_scanned: List[Endpoint]
    alerts_by_path: Dict[tuple[str, str, str], List[Dict[str, Any]]]
    scan_duration: float
    seqra_duration: Optional[float] = None
    total_messages_sent: Optional[int] = None

    @classmethod
    def from_endpoints(cls, endpoints: List[Endpoint],
                       alerts_by_path: Dict[tuple[str, str, str], List[Dict[str, Any]]],
                       scanned_endpoints: set, scan_duration: float, seqra_duration: Optional[float] = None,
                       total_messages_sent: Optional[int] = None):
        return cls(
            confirmed=[ep for ep in endpoints if alerts_by_path.get((ep.method, ep.path, ep.cwe))],
            unconfirmed=[ep for ep in endpoints if not alerts_by_path.get((ep.method, ep.path, ep.cwe)) and
                         (ep.method, ep.path, ep.cwe) in scanned_endpoints],
            not_scanned=[ep for ep in endpoints if (ep.method, ep.path, ep.cwe) not in scanned_endpoints],
            alerts_by_path=alerts_by_path,
            scan_duration=scan_duration,
            seqra_duration=seqra_duration,
            total_messages_sent=total_messages_sent
        )

    @property
    def total_endpoints(self) -> int:
        return len(self.confirmed) + len(self.unconfirmed) + len(self.not_scanned)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_endpoints": self.total_endpoints,
                "confirmed": len(self.confirmed),
                "unconfirmed": len(self.unconfirmed),
                "not_scanned": len(self.not_scanned),
                "scan_duration_seconds": self.scan_duration,
                "seqra_duration_seconds": self.seqra_duration,
                "total_messages_sent": self.total_messages_sent
            },
            "confirmed_vulnerabilities": [
                {
                    "endpoint": {
                        "method": ep.method,
                        "path": ep.path,
                        "cwe": ep.cwe,
                        "rule_id": ep.rule_id,
                        "rule_name": ep.rule_name,
                        "description": ep.description,
                        "risk_level": ep.risk_level,
                        "input_vectors": ep.input_vectors,
                        "scan_id": ep.scan_id,
                        "scan_error": ep.scan_error
                    },
                    "alerts": self.alerts_by_path.get((ep.method, ep.path, ep.cwe), [])
                }
                for ep in self.confirmed
            ],
            "unconfirmed_vulnerabilities": [
                {
                    "method": ep.method,
                    "path": ep.path,
                    "cwe": ep.cwe,
                    "rule_id": ep.rule_id,
                    "rule_name": ep.rule_name,
                    "description": ep.description,
                    "risk_level": ep.risk_level,
                    "input_vectors": ep.input_vectors,
                    "scan_id": ep.scan_id,
                    "scan_error": ep.scan_error
                }
                for ep in self.unconfirmed
            ],
            "not_scanned": [
                {
                    "method": ep.method,
                    "path": ep.path,
                    "cwe": ep.cwe,
                    "rule_id": ep.rule_id,
                    "rule_name": ep.rule_name,
                    "description": ep.description,
                    "risk_level": ep.risk_level,
                    "input_vectors": ep.input_vectors,
                    "scan_id": ep.scan_id,
                    "scan_error": ep.scan_error
                }
                for ep in self.not_scanned
            ]
        }

    def save_to_json(self, output_path: str) -> None:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"Results saved to: {output_path}")
        
        # Use GITHUB_OUTPUT environment file instead of deprecated set-output
        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"results_file={output_path}\n")


def print_scan_summary(results: ScanResults) -> None:
    if results.seqra_duration is not None:
        logger.info(f"Seqra scan: {results.seqra_duration:.2f}s")
    logger.info(f"ZAP scan: {results.scan_duration:.2f}s")
    if results.seqra_duration is not None:
        logger.info(f"Total: {results.seqra_duration + results.scan_duration:.2f}s")
    logger.info(f"Total endpoints: {results.total_endpoints}")
    logger.info(f"Confirmed vulnerabilities: {len(results.confirmed)}")
    logger.info(f"Not confirmed: {len(results.unconfirmed)}")
    if results.not_scanned:
        logger.info(f"Skipped: {len(results.not_scanned)}")
    if results.total_messages_sent:
        logger.info(f"Total HTTP requests: {results.total_messages_sent}")
    
    if results.confirmed:
        for ep in results.confirmed:
            alerts = results.alerts_by_path[(ep.method, ep.path, ep.cwe)]
            msg = f"{ep.method} {ep.path} - {ep.cwe} - {ep.rule_name} ({len(alerts)} alert(s))"
            log_warning(msg)
    
    if results.confirmed:
        log_notice(f"Security scan found {len(results.confirmed)} confirmed vulnerabilities. Check the full report for details.")
    else:
        log_notice("Security scan completed with no confirmed vulnerabilities.")




def start_zap_container(docker_image: str = "zaproxy/zap-stable", container_name: str = "zap-ci",
                        zap_port: int = 8080, zap_key: str = "", workspace: Optional[str] = None,
                        install_addons: bool = True) -> None:
    workspace = workspace or os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    logger.info(f"Pulling Docker image: {docker_image}")
    subprocess.run(["docker", "pull", docker_image, "-q"], check=True)
    
    zap_cmd_parts = []
    if install_addons:
        zap_cmd_parts.extend([
            "zap.sh -cmd -addonupdate",
            "zap.sh -cmd -addoninstall ascanrulesBeta",
            "zap.sh -cmd -addoninstall pscanrulesBeta"
        ])
    
    daemon_cmd = [
        f"zap.sh -daemon -host 0.0.0.0 -port {zap_port}",
        "-config api.addrs.addr.name=.*",
        "-config api.addrs.addr.regex=true",
        f"-config api.key={zap_key}" if zap_key else "-config api.disablekey=true"
    ]
    zap_cmd_parts.append(" ".join(daemon_cmd))
    
    docker_cmd = [
        "docker", "run", "-d", "--name", container_name, "--network", "host",
        "-v", f"{workspace}:/zap/wrk:rw", docker_image, "bash", "-c", " && ".join(zap_cmd_parts)
    ]
    
    logger.info(f"Starting ZAP container: {container_name}")
    result = subprocess.run(docker_cmd, capture_output=True, text=True, check=True)
    logger.info(f"ZAP container started: {result.stdout.strip()[:12]}")
    logger.info(f"ZAP URL: http://localhost:{zap_port}")
    
    logger.info("Waiting for ZAP to be ready...")
    time.sleep(60)
    max_wait = 30
    elapsed = 0
    while elapsed < max_wait:
        try:
            ZAPv2(apikey=zap_key, proxies={"http": f"http://localhost:{zap_port}", "https": f"http://localhost:{zap_port}"})
            logger.info("ZAP is ready!")
            break
        except Exception:
            time.sleep(2)
            elapsed += 2
    else:
        log_error("ZAP failed to start within timeout")
        raise RuntimeError("ZAP failed to start")


def stop_zap_container(container_name: str = "zap-ci") -> None:
    try:
        logger.info(f"Stopping container: {container_name}")
        subprocess.run(["docker", "stop", container_name], capture_output=True, check=False)
        subprocess.run(["docker", "rm", container_name], capture_output=True, check=False)
        logger.info("ZAP container stopped and removed")
    except Exception as e:
        log_warning(f"Failed to stop container: {e}")


class ScanScriptError(RuntimeError):
    pass


class ZapScanner:

    def __init__(self, zap_url: str, zap_key: str, cwe_scanners: Dict[str, List[int]], 
                 input_vector: int = 31, rpc: int = 5):
        self.zap = ZAPv2(apikey=zap_key, proxies={"http": zap_url, "https": zap_url})
        self.cwe_scanners = cwe_scanners
        self.input_vector = input_vector
        self.rpc = rpc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def check_missing_scanners(self) -> None:
        all_scanners = self.zap.ascan.scanners()
        available_scanner_ids = {int(s.get('id')) for s in all_scanners}
        required_scanner_ids = set()
        for scanner_list in self.cwe_scanners.values():
            required_scanner_ids.update(scanner_list)
        missing_scanners = required_scanner_ids - available_scanner_ids
        if missing_scanners:
            log_warning(f"Missing {len(missing_scanners)} scanner(s): {sorted(missing_scanners)}")
            log_warning("Missing rules will be ignored")

    def create_cwe_policies(self) -> Dict[str, str]:
        policies = {}
        for cwe, scanner_ids in self.cwe_scanners.items():
            policy_name = f"policy-{cwe}"
            if policy_name in self.zap.ascan.scan_policy_names:
                self.zap.ascan.remove_scan_policy(policy_name)
            self.zap.ascan.add_scan_policy(policy_name)
            self.zap.ascan.disable_all_scanners(scanpolicyname=policy_name)
            for scanner_id in scanner_ids:
                self.zap.ascan.enable_scanners(str(scanner_id), scanpolicyname=policy_name)
                self.zap.ascan.set_scanner_attack_strength(scanner_id, "INSANE", scanpolicyname=policy_name)
            policies[cwe] = policy_name
            logger.debug(f"Created policy '{policy_name}' with {len(scanner_ids)} scanners")
        return policies

    def import_openapi(self, openapi_source: str, target: str, context_id: Optional[str]) -> List[str]:
        if openapi_source.lower().startswith("http"):
            self.zap.openapi.import_url(url=openapi_source, hostoverride=target, contextid=context_id)
        else:
            openapi_path = Path(openapi_source).absolute()
            workspace = Path(os.getenv("GITHUB_WORKSPACE", os.getcwd()))
            relative_path = openapi_path.relative_to(workspace)
            zap_path = f"/zap/wrk/{relative_path}"
            logger.debug(f"Importing OpenAPI from container path: {zap_path}")
            self.zap.openapi.import_file(file=zap_path, target=target, contextid=context_id)
        urls = self.zap.core.urls(baseurl=target)
        logger.debug(f"Imported {len(urls)} urls to ZAP")
        return urls

    def create_scannable_endpoints_from_messages(self, target: str, sarif_endpoints: List[Endpoint],
                                                 start: int) -> tuple[List[Endpoint], List[Endpoint]]:
        """Create scannable endpoints by matching ZAP messages to SARIF endpoints"""
        logger.info("Analyzing ZAP messages to create scannable endpoints...")
        messages = self.zap.core.messages(baseurl=target, start=start)
        logger.debug(f"Retrieved {len(messages)} messages for target {target}")

        target_parsed = urlparse(target)
        base_path = target_parsed.path.rstrip('/')
        logger.debug(f"Base path from target: '{base_path}'")
        # Build lookup: (method, path) → [SARIF endpoints]
        sarif_lookup = {}
        for ep in sarif_endpoints:
            key = (ep.method.upper(), ep.path)
            if key not in sarif_lookup:
                sarif_lookup[key] = []
            sarif_lookup[key].append(ep)

        scannable_endpoints = []
        matched_keys = set()
        # For each ZAP message, create scannable endpoints
        for msg in messages:
            request_header = msg.get('requestHeader', '')
            if not request_header:
                continue
            # Parse first line: "METHOD URL HTTP/1.1"
            first_line = request_header.split('\r\n')[0]
            parts = first_line.split(' ')
            if len(parts) < 2:
                continue
            method = parts[0].upper()
            full_url = parts[1]
            zap_path = urlparse(full_url).path
            postdata = msg.get('requestBody', '') or None
            if base_path and zap_path.startswith(base_path):
                sarif_path = zap_path[len(base_path):]
            else:
                sarif_path = zap_path

            key = (method, sarif_path)
            if key not in sarif_lookup:
                continue
            
            matched_keys.add(key)
            
            # Create one scannable endpoint per SARIF endpoint (per CWE)
            for sarif_ep in sarif_lookup[key]:
                scannable_ep = Endpoint(
                    cwe=sarif_ep.cwe,
                    method=method,
                    path=sarif_ep.path,
                    input_vectors=sarif_ep.input_vectors,
                    rule_id=sarif_ep.rule_id,
                    rule_name=sarif_ep.rule_name,
                    description=sarif_ep.description,
                    risk_level=sarif_ep.risk_level,
                    matched_url=full_url,
                    postdata=postdata
                )
                scannable_endpoints.append(scannable_ep)
        
        # Find unmatched SARIF endpoints
        unmatched = []
        for key, sarif_eps in sarif_lookup.items():
            if key not in matched_keys:
                unmatched.extend(sarif_eps)
        logger.info(f"Created {len(scannable_endpoints)} scannable endpoints from {len(messages)} new messages")
        if unmatched:
            logger.warning(f"{len(unmatched)} SARIF endpoint(s) not found in ZAP messages:")
            for ep in unmatched[:5]:
                logger.warning(f"  - {ep.method} {ep.path} ({ep.cwe})")
            if len(unmatched) > 5:
                logger.warning(f"  ... and {len(unmatched) - 5} more")
        return scannable_endpoints, unmatched

    def _submit_scan(self, url: str, context_id: Optional[str], user_id: Optional[str],
                     policy_name: str, method: str, postdata: Optional[str] = None) -> Optional[str]:
        """Submit a single scan to ZAP"""
        if user_id:
            return self.zap.ascan.scan_as_user(
                url=url,
                contextid=context_id,
                userid=user_id,
                recurse=False,
                scanpolicyname=policy_name,
                method=method,
                postdata=postdata
            )
        return self.zap.ascan.scan(
            url=url,
            recurse=False,
            contextid=context_id,
            scanpolicyname=policy_name,
            method=method,
            postdata=postdata
        )

    def scan_endpoint(self, endpoints: List[Endpoint], cwe_policies: Dict[str, str],
                      context_id: Optional[str], user_id: Optional[str]) -> tuple[List[str], set, float]:
        """Scan endpoints with controlled parallelism matching recurse=True behavior"""
        scan_start_time = time.time()
        scanned_endpoints = set()
        all_scan_ids = []
        self.scan_message_counts = {}
        max_workers = int(self.zap.ascan.option_thread_per_host)
        
        # Set each scan to use 1 thread to avoid oversubscription
        self.zap.ascan.set_option_thread_per_host(1)
        self.zap.ascan.set_option_target_params_injectable(self.input_vector)
        self.zap.ascan.set_option_target_params_enabled_rpc(self.rpc)

        logger.info(f"Scanning with {max_workers} parallel workers (1 thread per scan)")
        logger.info(f"Input vector mask: {self.input_vector}, RPC: {self.rpc}")

        def scan_single_endpoint(endpoint: Endpoint) -> Optional[str]:
            if not endpoint.is_scannable:
                logger.warning(f"Skipping {endpoint.method} {endpoint.path} - no matched URL")
                endpoint.scan_error = "no_matched_url"
                return None

            logger.info(f"{endpoint.method} {endpoint.path} - CWE: {endpoint.cwe}")
            policy_name = cwe_policies.get(endpoint.cwe)
            if not policy_name:
                logger.warning(f"  [{endpoint.cwe}] No policy found")
                endpoint.scan_error = "no_policy"
                return None
            raw_scan_id = self._submit_scan(endpoint.matched_url, context_id, user_id, policy_name, endpoint.method,
                                            endpoint.postdata)
            scan_id = str(raw_scan_id).strip() if raw_scan_id is not None else ""
            if not scan_id.isdigit():
                endpoint.scan_error = scan_id or "scan_failed"
                logger.error(f"  [{endpoint.cwe}] Scan failed: {endpoint.scan_error}")
                return None
            endpoint.scan_id = scan_id
            scanned_endpoints.add((endpoint.method, endpoint.path, endpoint.cwe))
            logger.debug(f"  [{endpoint.cwe}] Scan {scan_id} started")

            delay = 1
            while True:
                status = int(self.zap.ascan.status(scan_id))
                if status == 100:
                    break
                if status > 90:
                    delay = 0.2
                time.sleep(delay)
            logger.debug(f"  [{endpoint.cwe}] Scan {scan_id} completed")

            message_ids = self.zap.ascan.messages_ids(scan_id)
            self.scan_message_counts[scan_id] = len(message_ids)
            logger.debug(f"  [{endpoint.cwe}] Scan {scan_id} sent {len(message_ids)} messages")
            return scan_id

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(scan_single_endpoint, ep) for ep in endpoints]
            for future in as_completed(futures):
                scan_id = future.result()
                if scan_id:
                    all_scan_ids.append(scan_id)

        self.zap.ascan.set_option_thread_per_host(max_workers)

        return all_scan_ids, scanned_endpoints, scan_start_time
    
    def get_total_messages_sent(self) -> int:
        """Get total number of messages sent during all scans"""
        total_messages = sum(self.scan_message_counts.values())
        logger.info(f"Total messages sent during scans: {total_messages}")
        return total_messages

    def get_alerts_for_endpoints(self, endpoints: List[Endpoint]) -> Dict[tuple[str, str, str], List[Dict[str, Any]]]:
        """Fetch full alert payloads for every scanned endpoint by scan ID."""
        alerts_by_endpoint: Dict[tuple[str, str, str], List[Dict[str, Any]]] = {}
        total_alerts = 0

        for ep in endpoints:
            key = (ep.method, ep.path, ep.cwe)
            if key not in alerts_by_endpoint:
                alerts_by_endpoint[key] = []

            if not ep.scan_id:
                continue

            alert_ids = self.zap.ascan.alerts_ids(ep.scan_id)
            full_alerts = [self.zap.core.alert(alert_id) for alert_id in alert_ids]
            alerts_by_endpoint[key].extend(full_alerts)
            total_alerts += len(full_alerts)

        logger.info(f"Retrieved {total_alerts} total alerts for {len(endpoints)} endpoints")
        return alerts_by_endpoint

    def setup_context(self) -> str:
        """Setup ZAP context and return context ID"""
        contexts = self.zap.context.context_list
        name = "seqra"
        if name in contexts:
            self.zap.context.remove_context(name)
        self.zap.context.new_context(name)
        logger.info(f"Created new context: {name}")

        ctx_info = self.zap.context.context(name)
        if isinstance(ctx_info, str):
            ctx_info = json.loads(ctx_info)

        return ctx_info["id"]



def parse_sarif(sarif_path: str, cwe_scanners: Dict[str, List[int]]) -> List[Endpoint]:
    data = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    endpoints = {}
    rule_metadata = {}
    for run in data["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            cwes = [t for t in rule["properties"]["tags"] if t.startswith("CWE-")]
            if cwes:
                rule_metadata[rule["id"]] = {
                    "cwes": cwes,
                    "name": rule.get("name", rule["id"]),
                    "description": rule.get("shortDescription", {}).get("text", "")
                }
    for run in data["runs"]:
        for result in run["results"]:
            rule_id = result["ruleId"]
            metadata = rule_metadata.get(rule_id)
            if not metadata:
                continue
            cwes = [cwe for cwe in metadata["cwes"] if cwe in cwe_scanners]
            if not cwes:
                continue
            risk_level = result.get("level", "warning")
            if "relatedLocations" not in result:
                continue
            for related in result["relatedLocations"]:
                for loc in related["logicalLocations"]:
                    fqn = loc["fullyQualifiedName"]
                    if " " not in fqn:
                        continue
                    method, path = fqn.split(" ", 1)
                    input_mask = 31
                    for cwe in cwes:
                        key = (method, path, cwe)
                        if key not in endpoints:
                            endpoints[key] = Endpoint(
                                cwe=cwe, method=method, path=path, input_vectors=input_mask,
                                rule_id=rule_id, rule_name=metadata["name"],
                                description=metadata["description"], risk_level=risk_level
                            )
    return list(endpoints.values())


def extract_vulnerability_hashes(sarif_path: str, cwe_scanners: Dict[str, List[int]]) -> Dict[str, Dict[str, Any]]:
    data = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    vulnerabilities = {}
    rule_metadata = {}
    for run in data["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            cwes = [t for t in rule["properties"]["tags"] if t.startswith("CWE-")]
            if cwes:
                rule_metadata[rule["id"]] = {
                    "cwes": cwes,
                    "name": rule.get("name", rule["id"]),
                    "description": rule.get("shortDescription", {}).get("text", "")
                }
    for run in data["runs"]:
        for result in run["results"]:
            partial_fingerprints = result.get("partialFingerprints", {})
            vuln_hash = partial_fingerprints.get("vulnerabilityWithTraceHash/v1")
            if not vuln_hash:
                continue
            rule_id = result["ruleId"]
            metadata = rule_metadata.get(rule_id)
            if not metadata:
                continue
            cwes = [cwe for cwe in metadata["cwes"] if cwe in cwe_scanners]
            if not cwes:
                continue
            risk_level = result.get("level", "warning")
            if "relatedLocations" not in result:
                continue
            for related in result["relatedLocations"]:
                for loc in related["logicalLocations"]:
                    fqn = loc["fullyQualifiedName"]
                    if " " not in fqn:
                        continue
                    method, path = fqn.split(" ", 1)
                    vulnerabilities[vuln_hash] = {
                        "method": method, "path": path, "cwes": cwes,
                        "rule_id": rule_id, "rule_name": metadata["name"],
                        "description": metadata["description"], "risk_level": risk_level
                    }
    return vulnerabilities


def get_new_vulnerabilities(old_sarif: str, new_sarif: str, cwe_scanners: Dict[str, List[int]]) -> List[Endpoint]:
    logger.info("Comparing SARIF files for differential scan")
    logger.info(f"  Old (base): {old_sarif}")
    logger.info(f"  New (PR):   {new_sarif}")
    old_vulns = extract_vulnerability_hashes(old_sarif, cwe_scanners)
    new_vulns = extract_vulnerability_hashes(new_sarif, cwe_scanners)
    logger.info(f"Old SARIF contains {len(old_vulns)} vulnerabilities")
    logger.info(f"New SARIF contains {len(new_vulns)} vulnerabilities")
    new_hashes = set(new_vulns.keys()) - set(old_vulns.keys())
    logger.info(f"Found {len(new_hashes)} new/changed vulnerabilities")
    endpoints = {}
    for vuln_hash in new_hashes:
        vuln = new_vulns[vuln_hash]
        for cwe in vuln["cwes"]:
            key = (vuln["method"], vuln["path"], cwe)
            if key not in endpoints:
                endpoints[key] = Endpoint(
                    cwe=cwe, method=vuln["method"], path=vuln["path"], input_vectors=31,
                    rule_id=vuln["rule_id"], rule_name=vuln["rule_name"],
                    description=vuln["description"], risk_level=vuln["risk_level"]
                )
    return list(endpoints.values())


def filter_endpoints(endpoints: List[Endpoint]) -> List[Endpoint]:
    """Return all endpoints (no filtering)"""
    return endpoints


def main():
    parser = argparse.ArgumentParser(description="Scan API endpoints with ZAP (CI mode with differential scanning)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Read configuration from environment variables
    new_sarif = os.getenv("NEW_SARIF")
    old_sarif = os.getenv("OLD_SARIF")
    openapi_spec = os.getenv("OPENAPI_SPEC")
    target_url = os.getenv("TARGET_URL")
    input_vector = int(os.getenv("INPUT_VECTOR", "31"))
    rpc = int(os.getenv("RPC", "5"))
    cwe_config = os.getenv("CWE_CONFIG")
    output_file = os.getenv("OUTPUT_FILE", "reports/scan-results.json")
    
    # Validate required parameters
    if not new_sarif:
        log_error("NEW_SARIF environment variable is required")
        raise SystemExit(1)
    if not openapi_spec:
        log_error("OPENAPI_SPEC environment variable is required")
        raise SystemExit(1)
    if not target_url:
        log_error("TARGET_URL environment variable is required")
        raise SystemExit(1)
    if not cwe_config:
        log_error("CWE_CONFIG environment variable is required")
        raise SystemExit(1)

    cwe_scanners = load_cwe_scanners(cwe_config)
    docker_image = "zaproxy/zap-stable"
    container_name = "zap-ci"
    zap_port = 8080
    zap_key = ""
    zap_url = f"http://localhost:{zap_port}"

    try:
        start_zap_container(docker_image, container_name, zap_port, zap_key, install_addons=True)

        if old_sarif:
            logger.info("Differential scanning mode enabled")
            raw_endpoints = get_new_vulnerabilities(old_sarif, new_sarif, cwe_scanners)
            logger.info(f"Found {len(raw_endpoints)} new endpoints after differential analysis")
        else:
            logger.info(f"Parsing SARIF: {new_sarif}")
            raw_endpoints = parse_sarif(new_sarif, cwe_scanners)
            logger.info(f"Found {len(raw_endpoints)} endpoints from SARIF")

        filtered_endpoints = filter_endpoints(raw_endpoints)
        logger.info(f"Processing {len(filtered_endpoints)} endpoints")
        if not filtered_endpoints:
            log_error("No endpoints to scan")
            return

        logger.info(f"Connecting to ZAP at {zap_url}")
        with ZapScanner(zap_url, zap_key, cwe_scanners, input_vector, rpc) as scanner:
            scanner.check_missing_scanners()
            context_id = scanner.setup_context()
            messages_before_openapi = scanner.zap.core.number_of_messages(baseurl=target_url)
            logger.debug(f"Existing messages before OpenAPI import: {messages_before_openapi}")
            logger.info("Importing OpenAPI spec to ZAP")
            zap_urls = scanner.import_openapi(openapi_spec, target_url, context_id)
            logger.debug(f"ZAP discovered {len(zap_urls)} URLs")
            logger.info(f"Creating policies for {len(cwe_scanners)} CWE categories")
            cwe_policies = scanner.create_cwe_policies()
            scannable_endpoints, not_found = scanner.create_scannable_endpoints_from_messages(
                target_url, filtered_endpoints, start=messages_before_openapi
            )
            if not scannable_endpoints:
                log_error("No scannable endpoints created from ZAP messages - cannot scan")
                return
            
            logger.info(f"Starting scan of {len(scannable_endpoints)} endpoints")
            all_scan_ids, scanned_endpoints, scan_start_time = scanner.scan_endpoint(
                scannable_endpoints, cwe_policies, context_id, None
            )
            scan_duration = time.time() - scan_start_time
            logger.info(f"All scans completed in {scan_duration:.2f}s")
            total_messages_sent = scanner.get_total_messages_sent()
            
            all_endpoints = scannable_endpoints + not_found
            alerts_by_path = scanner.get_alerts_for_endpoints(all_endpoints)
            results = ScanResults.from_endpoints(
                all_endpoints, alerts_by_path, scanned_endpoints, scan_duration, None, total_messages_sent
            )
            
            results.save_to_json(output_file)
            print_scan_summary(results)
        
        log_notice("Scan complete")
    finally:
        stop_zap_container(container_name)


if __name__ == "__main__":
    main()
