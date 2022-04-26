%lang starknet

from starkware.starknet.common.syscalls import get_caller_address, get_contract_address
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from contracts.IERC20 import IERC20

const GOERLI_WETH_ADDRESS = 123

@external
func deposit_eth{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(amount : felt):
    let (caller_address) = get_caller_address()
    let (contract_address) = get_contract_address()
    let uint256_amount = Uint256(amount, 0)
    IERC20.transferFrom(contract_address = GOERLI_WETH_ADDRESS, sender=caller_address, recipient=contract_address, amount=uint256_amount)
    return ()
end
