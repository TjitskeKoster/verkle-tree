
# VerkleTree
VerkleTree is a Rust library implementing Verkle Trees using the BLS12-381 elliptic curve and KZG commitments for efficient storage and verification of data. This library provides functionality to build a Verkle Tree, generate proofs, and verify them.

### Features
- Verkle Tree Construction: Build a Verkle Tree from a set of data.
- Proof Generation: Generate proofs for specific data points in the Verkle Tree.
- Proof Verification: Verify the generated proofs.

### Installation
To use this library, add the following to your `Cargo.toml`
```toml
verkle-tree = "0.1.0"
```

### Usage
See main.rs for a basic example of how to use the library.
KZG proofs will be slower than the pointproofs. 

### Debugging
``` assertion failed: self.coeffs.last().map_or(false, |coeff| !coeff.is_zero()) ```
Take different data, the KZG proofs made a trivial polynomial which it is unable to proof. 

### Testing
To run the tests, use the following command:
```bash
cargo test
```

### TODO
- [ ] Add support for multiproof using random evaluation
- [ ] Store VerkleTree
- [ ] Add benchmarks in comparison to Merkle Trees
- [ ] VerkleTree solidity verifier???


### Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.