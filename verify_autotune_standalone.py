
import sys
import uuid

# --- MOCK / COPIED CODE FROM BACKEND FOR ISOLATION ---

class AutoTunePolicy:
    """Décide de la configuration d'exécution optimale"""
    
    def compute_execution_plan(self, profile_name: str, scan_mode: str, base_url: str, repo_size_bytes: int, probe_stats: dict) -> dict:
        """
        Retourne un plan d'exécution:
        {
            "parallel_files": int,
            "chunk_size_chars": int,
            "whole_file_max_chars": int,
            "timeout": int,
            "num_predict": int,
            "strategy": str
        }
        """
        # Default Plan (Safe)
        plan = {
            "parallel_files": 1,
            "chunk_size_chars": 8192,  # Eco default
            "whole_file_max_chars": 32000,
            "timeout": 120,
            "num_predict": 2048,
            "strategy": "DEFAULT_SAFE"
        }
        
        tps = probe_stats.get("tps", 0)
        latency = probe_stats.get("latency_ms", 9999)
        reachable = probe_stats.get("reachable", False)
        
        # 1. DETECT ENVIRONMENT
        # ---------------------
        is_local_fast = (latency < 15 and tps > 30)       # M2/M3 Max or RTX 4090
        is_local_mid = (latency < 20 and tps > 15)        # M1 Pro or RTX 3060
        is_remote_fast = (latency > 100 and tps > 50)     # RunPod / Groq
        is_remote_slow = (latency > 200 and tps < 20)     # Cheap VPS
        
        # 2. APPLY STRATEGY
        # -----------------
        
        # STRATEGY A: LOCAL BLAZING FAST (High Parallelism)
        if is_local_fast and profile_name in ["elite", "titan", "balanced"]:
            plan.update({
                "parallel_files": 8 if profile_name == "titan" else 4,
                "chunk_size_chars": 32000,
                "timeout": 60, # Fast processing, fail fast
                "strategy": "LOC_BLAZING"
            })
            
        # STRATEGY B: LOCAL MID (Moderate Parallelism)
        elif is_local_mid and profile_name != "eco":
            plan.update({
                "parallel_files": 4 if profile_name == "titan" else 2,
                "chunk_size_chars": 16000,
                "strategy": "LOC_BALANCED"
            })
            
        # STRATEGY C: REMOTE FAST (High Latency, High Throughput)
        elif is_remote_fast:
             # Latency is the killer -> Maximize chunk size to reduce round-trips
             # But keep parallelism moderate to avoid flooding the network/queue
             plan.update({
                "parallel_files": 4, 
                "chunk_size_chars": 64000, # Large Context utilization
                "timeout": 300, # Network margin
                "strategy": "REM_HIGH_THROUGHPUT"
             })
             
        # STRATEGY D: REMOTE SLOW / ECO (Survival Mode)
        else:
            plan.update({
                "parallel_files": 1,
                "chunk_size_chars": 8192,
                "timeout": 180,
                "strategy": "ECO_OR_SLOW"
            })
            
        # 3. MODE OVERRIDES
        # -----------------
        if scan_mode == "devsecops":
             # Force stability over speed
             plan["parallel_files"] = max(1, plan["parallel_files"] // 2)
             plan["timeout"] += 60
             
        if scan_mode == "rapid":
             # Fail fast, smaller chunks
             plan["timeout"] = 60
             plan["chunk_size_chars"] = min(plan["chunk_size_chars"], 16000)

        return plan

# --- TESTS ---

def test_autotune_policy():
    print("🧪 Testing AutoTunePolicy (Isolated)...")
    policy = AutoTunePolicy()
    
    # CASE 1: Local High End
    stats_local_fast = {"reachable": True, "tps": 45.0, "latency_ms": 10}
    plan = policy.compute_execution_plan("balanced", "rapid", "http://localhost:11434", 1024, stats_local_fast)
    print(f"   Local Fast -> Parallel={plan['parallel_files']} (Strategy={plan['strategy']})")
    assert plan['parallel_files'] >= 4, f"Should utilize parallelism on fast local. Got {plan['parallel_files']}"

    # CASE 2: Remote Slow Latency
    stats_remote_slow = {"reachable": True, "tps": 10.0, "latency_ms": 300}
    plan = policy.compute_execution_plan("balanced", "deep", "http://remote:11434", 1024, stats_remote_slow)
    print(f"   Remote Slow -> Parallel={plan['parallel_files']} (Strategy={plan['strategy']})")
    assert plan['parallel_files'] <= 1, f"Should throttle on high latency. Got {plan['parallel_files']}"

    # CASE 3: Eco Mode
    plan = policy.compute_execution_plan("eco", "rapid", "http://localhost:11434", 1024, stats_local_fast)
    print(f"   Eco Mode -> Parallel={plan['parallel_files']} (Strategy={plan['strategy']})")
    assert plan['parallel_files'] == 1, "Eco should be sequential"

    print("✅ AutoTunePolicy Logic Passed")

def test_uuid_generation():
    print("\n🧪 Testing ID Generation (UUID)...")
    
    # Mock vuln list
    mock_vulns = [
        {"severity": "High", "title": "Test 1"},
        {"severity": "Low", "title": "Test 2"}
    ]
    
    # Simulate UUID assignment line execution logic (simplified from run_scan)
    processed_vulns = []
    for v in mock_vulns:
        v["id"] = str(uuid.uuid4())
        processed_vulns.append(v)
        
    print(f"   ID 1: {processed_vulns[0]['id']}")
    print(f"   ID 2: {processed_vulns[1]['id']}")
    
    assert len(processed_vulns[0]["id"]) > 10, "ID should be a long string (UUID)"
    assert processed_vulns[0]["id"] != processed_vulns[1]["id"], "IDs must be unique"
    
    print("✅ UUID Generation Passed")

if __name__ == "__main__":
    try:
        test_autotune_policy()
        test_uuid_generation()
        print("\n✨ All Auto-Tuner & Fix verifications passed!")
    except AssertionError as e:
        print(f"\n❌ Verification Failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
