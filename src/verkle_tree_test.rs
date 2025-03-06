#[cfg(test)]
mod tests {

    use crate::VerkleTree;
    use ark_bls12_381::Fr as F;
    use rand::Rng;
    use random_number::random;
    use rand::prelude::*;

    #[test]
    fn test_build_tree() {
        let (tree, _, _, _) = build_verkle_tree();
        assert!(
            tree.root_commitment().is_some(),
            "Failed building verkle tree"
        );
    }

    #[test]
    fn test_generate_proof() {
        let (tree, datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let random_point = datas[ranom_index];
        let proof = tree.generate_proof(ranom_index, &random_point);
        assert!(proof.is_ok(), "Proof Generation failed");
    }

    #[test]
    fn test_generate_invalid_proof() {
        let (tree, _datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let fake_point = F::from(rng.gen_range(-100..=100));
        let proof = tree.generate_proof(ranom_index, &fake_point);
        assert!(
            proof.is_err(),
            "Should not be able to generate a valid proof"
        );
    }

    #[test]
    fn test_verify_proof() {
        let (tree, datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let random_point = datas[ranom_index];
        let proof = tree.generate_proof(ranom_index, &random_point).unwrap();
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_proof(root, &proof, width);

        assert!(verification, "Given point should generate a valid proof");
    }

    #[test]
    fn test_invalid_proof_verification() {
        let (tree, _, _, _) = build_verkle_tree();
        let (invalid_tree, datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let random_point = datas[ranom_index];
        let proof = invalid_tree.generate_proof(ranom_index, &random_point);
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_proof(root,&proof.unwrap(), width);

        assert_eq!(verification, false, "Should not accept invalid proof");
    }

    fn build_verkle_tree() -> (VerkleTree, Vec<F>, usize, usize) {
        let mut rng = rand::thread_rng();
        let width = rng.gen_range(2..=20);
        let length = rng.gen_range(2..=20);
        println!("Generating tree with length {} and width {}", length, width);
        let datas = generate_random_vec(length * width);
        (VerkleTree::new(&datas, width).unwrap(), datas, width, length)
    }

    fn generate_random_vec(length: usize) -> Vec<F> {
        let mut rng = rand::thread_rng();
        println!("Generating vector with length: {}", length);
        (0..length)
            .map(|_| F::from(rng.gen_range(-100..=100)))
            .collect()
    }

    #[test]
    fn test_batch_proof_verify() {
        let (tree, datas, length, width) = build_verkle_tree();
        let indices: Vec<usize> = (0..=(length * width-1) as usize).choose_multiple(&mut thread_rng(),datas.len()*(0.2)as usize);
        // let random_point: Vec<F> = Vec::new;
        // for ind in indices{
        //     random_point.push(datas[ind]);
        // }
        let proof = tree.generate_batch_proof(indices, &datas);
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_batch_proof(root, proof, width);
        assert!(verification, "Given point should generate a valid proof");
    }

}
