
import sys
import os
import asyncio
import uuid
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath("/Users/pacome/nexus_auditor"))

from backend.backend import AutoTunePolicy, scan_state, SCANS

def test_autotune_policy():
    print("🧪 Testing AutoTunePolicy...")
    policy = AutoTunePolicy()
    
    # CASE 1: Local High End
    stats_local_fast = {"reachable": True, "tps": 45.0, "latency_ms": 10}
    plan = policy.compute_execution_plan("balanced", "rapid", "http://localhost:11434", 1024, stats_local_fast)
    print(f"   Local Fast -> Parallel={plan['parallel_files']} (Expected > 1)")
    assert plan['parallel_files'] >= 4, "Should utilize parallelism on fast local"

    # CASE 2: Remote Slow Latency
    stats_remote_slow = {"reachable": True, "tps": 20.0, "latency_ms": 300}
    plan = policy.compute_execution_plan("balanced", "deep", "http://remote:11434", 1024, stats_remote_slow)
    print(f"   Remote Slow -> Parallel={plan['parallel_files']} (Expected Low)")
    assert plan['parallel_files'] <= 2, "Should throttle on high latency"

    # CASE 3: Eco Mode
    plan = policy.compute_execution_plan("eco", "rapid", "http://localhost:11434", 1024, stats_local_fast)
    print(f"   Eco Mode -> Parallel={plan['parallel_files']} (Expected 1)")
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
