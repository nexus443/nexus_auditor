import requests
import time
import sys

# Copy of the class for standalone testing
class OllamaCapabilityProbe:
    """Mesure les performances réelles du serveur Ollama (Local ou Remote)"""
    def __init__(self, base_url: str, model: str, timeout: int = 15):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout
        self.session = requests.Session()

    def run(self) -> dict:
        stats = {
            "reachable": False,
            "model_available": False,
            "rtt_ms": 0,
            "tokens_per_sec_est": 0,
            "stability_score": 0
        }
        
        print(f"[*] Probing {self.base_url} for model {self.model}...")

        # 1. Reachability Check (Ping /tags)
        try:
            start_ping = time.time()
            tags_url = f"{self.base_url}/api/tags"
            
            print(f"    -> GET {tags_url} (timeout=10s)")
            resp = self.session.get(tags_url, timeout=(5, 10))
            
            if resp.status_code == 200:
                stats["reachable"] = True
                stats["rtt_ms"] = int((time.time() - start_ping) * 1000)
                print(f"    <- OK (RTT: {stats['rtt_ms']}ms)")
                
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                if any(self.model in str(m) for m in models):
                    stats["model_available"] = True
                    print(f"    <- Model {self.model} found.")
                else:
                    print(f"    <- Model {self.model} NOT found (available: {', '.join(models[:3])}...)")
            else:
                print(f"    <- FAIL: HTTP {resp.status_code}")
                
        except Exception as e:
            print(f"    <- ERROR: {e}")
            return stats

        # 2. Micro-Benchmark
        if stats["reachable"]:
            try:
                gen_url = f"{self.base_url}/api/generate"
                payload = {
                    "model": self.model,
                    "prompt": "Return exactly the word: OK", 
                    "stream": False, 
                    "options": {"num_predict": 16, "temperature": 0, "num_ctx": 256}
                }
                
                print(f"    -> POST {gen_url} (Benchmark, stream=False)")
                start_gen = time.time()
                resp = self.session.post(gen_url, json=payload, timeout=(5, 30))
                duration = time.time() - start_gen
                
                if resp.status_code == 200:
                    data = resp.json()
                    eval_count = data.get("eval_count", 0)
                    eval_duration = data.get("eval_duration", 0)
                    
                    if eval_duration > 0:
                        tps = eval_count / (eval_duration / 1e9)
                    else:
                        tps = eval_count / duration if duration > 0 else 0
                        
                    stats["tokens_per_sec_est"] = round(tps, 2)
                    print(f"    <- OK: Speed {stats['tokens_per_sec_est']} t/s")
                else:
                    print(f"    <- FAIL: HTTP {resp.status_code}")

            except Exception as e:
                print(f"    <- ERROR: {e}")

        return stats

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:11434"
    model = sys.argv[2] if len(sys.argv) > 2 else "qwen2.5-coder:7b"
    
    probe = OllamaCapabilityProbe(url, model)
    result = probe.run()
    print("\nFINAL STATS:", result)
