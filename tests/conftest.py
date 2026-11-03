from pathlib import Path
import pytest
from genvm_linter.validate.sdk_loader import load_sdk, load_contract_module
PATH = Path(__file__).resolve().parents[1] / 'contracts/change_gate.py'
load_sdk(PATH)
cg = load_contract_module(PATH)

@pytest.fixture
def cg_module():
    return cg
