use std::alloc::Layout;
use std::time::Instant;
use std::{collections::HashSet, vec};

use pairing_plus::serdes::SerDes;

use pointproofs::pairings::*;
use pointproofs::pairings::Commitment;
use rayon::prelude::*;

//#[derive(Debug, Clone)]
pub struct VerkleTree {
    nodes: Vec<Vec<VerkleNode>>,
    width: usize,
    pp: ProverParams,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: Commitment,
    children: bool,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub proofs: Vec<ProofNode>,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub commitment: Commitment, 
    pub proof: Proof, 
    pub indices : Vec<usize>,
    pub values: Vec<Vec<u8>> , //(index:usize, value: vec<vec<u8>>)
}

impl VerkleTree {
    // Initialize a new tree
    pub fn new(datas: &[Vec<u8>], width: usize, prover_params: ProverParams) -> Result<Self, VerkleTreeError> {
        //println!("start building");
        Self::build_tree(prover_params, datas, width)
    }

    fn build_tree(prover_params: ProverParams, datas: &[Vec<u8>], width: usize) -> Result<VerkleTree, VerkleTreeError> {
        if datas.is_empty() {
          return Err(VerkleTreeError::BuildError);
        }
        assert!(datas.len().is_multiple_of(width), "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number otherwise security can not be guaranteed");
        
        // We build the tree layer per layer
        //println!("Start making the first layer with no children");
        let mut layer = Self::create_leaf_nodes(&prover_params, datas.to_vec(), width);
        //println!("first layer is constructed");
        let mut tree: Vec<Vec<VerkleNode>> = Vec::new();
        tree.push(layer.clone());
        while layer.len() > 1 {
            layer = Self::build_layer(&prover_params, &layer, width);
            tree.push(layer.clone());
            //println!("next layer is constructed");
        }
        // to get the root as first index.
        tree.reverse();
        //tree = Self::add_incides(tree);
        
        Ok(VerkleTree {
            nodes: tree,
            width,
            pp: prover_params,
        })
    }

    // fn add_incides( tree: Vec<VerkleNode>) -> Vec<VerkleNode>{
    //     tree
    // }
    
    fn create_leaf_nodes(prover_params: &ProverParams, datas: Vec<Vec<u8>>, width: usize) -> Vec<VerkleNode> {
        datas
            .par_chunks(width)
            .map(|chunk| {
                let values = chunk.to_vec();
                let commitment: Commitment = Commitment::new(prover_params, &values).unwrap();
                VerkleNode {
                    commitment,
                    //values,
                    children: false,
                    //index: 0,
                }
            })
            .rev().collect()
    }

    fn build_layer(prover_params: &ProverParams, nodes: &[VerkleNode], width: usize) -> Vec<VerkleNode> {
        nodes
        .par_chunks(width)
            .map(|chunk| {
                let values: Vec<Vec<u8>> = chunk
                    .iter()
                    .map(|node| Self::map_commitment_to_vec_u8(&node.commitment))
                    .collect();
                let commitment: Commitment = Commitment::new(prover_params, &values).unwrap();
                VerkleNode {
                    commitment,
                    //values,
                    children: true,
                    //index: 0,
                }
            })
            .rev().collect()
    }
/* The next functions are to generate proofs for several indices simultaeusly  */

    /*  This function returns a long vector which reads the nodes from top to bottom left to right
        Each index contains either a proof of some children, or a None value
    */
    pub fn proof (&self, index: Vec<usize>, data: &[Vec<u8>]) -> Vec<Option<ProofNode>> {
        assert!(data.len().is_multiple_of(self.width), "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");
        assert!(!index.is_empty(), "Please give a non empty index");
        let width = self.width;
        // The following line creates a vector, on each index is a vector which incidates which children nodes need to be proven
        //println!("create index for proof");
        let index_for_proof = VerkleTree::create_index_for_proof(index, width, self.depth());
        //println!("done creating indices");
        let tree = self.nodes.clone();
        // for i in tree.clone(){
        //     for node in i {
        //         println!("{}", node.children);
        //     }
        // }
        //println!("tree {:?}", tree);

        /* We observe that we can compute each node in parallel, so first we flatten the tree structure
            While, perserving the layer and node index */
        let flattened_tree: Vec<(usize, usize, &VerkleNode)> = tree.iter()
            .enumerate()
            .flat_map(|(layer_index,layer)|{
                layer.iter().enumerate().map(move |(node_index, node)| (layer_index, node_index, node))
            }).collect();
        
        flattened_tree.par_iter().map(|(layer_index, node_index, node)|{
            let mut values:Vec<Vec<u8>> = Vec::new();
            let indices: &Vec<usize> = &index_for_proof[*layer_index][*node_index];
            let mut proof_indices: Vec<usize> = Vec::new();
                for index in indices{
                    proof_indices.push(index % width);
                }
            if indices.is_empty() {
                None
            }
            else if node.children {
                for i in 0 .. width{
                    let com = &tree[layer_index+1][i].commitment;
                    let child_commitment = Self::map_commitment_to_vec_u8(&com);
                    values.push(child_commitment);
                }
                Some(self.proof_node(&node.commitment, values, &proof_indices).expect("failed to generate proof for node"))
            }
            else {
                // no children so values from the data
                for i in 0 .. width{
                    values.push(data[i].clone());
                }
                Some(self.proof_node(&node.commitment, values, &proof_indices).expect("failed to generate proof for node"))
                }
        }).collect()
        
    }

    fn proof_node(&self, commit:&Commitment, values: Vec<Vec<u8>>, indices: &Vec<usize>) -> Result<ProofNode, VerkleTreeError>{
        let proof = Proof::batch_new_aggregated(&self.pp, commit, &values, indices);
        match proof {
            Ok(proof) => {
                let proof_node = ProofNode {
                    commitment: commit.clone(),
                    proof,
                    indices: indices.to_vec(),
                    values,
                };
                Ok(proof_node)
            }
            Err(_) => Err(VerkleTreeError::ProofGenerateError),
        }
    }

    fn create_index_for_proof(index: Vec<usize>, width: usize, depth: usize) -> Vec<Vec<Vec<usize>>> {

        /* For widht = 3, depth=2 index = [1,2,6] This creates:
            [[[0, 2]],
                [[1, 2], [], [6]]]
            The first vector is the root, this node needs to prove children on position 0 adn 2 of the next layer.
            The second vector is the second layer, need to prove node 1, 2 and 6 of the next layer in this case the data set
            */
        let mut tree_path: Vec<Vec<Vec<usize>>>  = Vec::new();
        let mut indexes = index.clone();
        for level in 2.. (depth+1){
            let data_level_above = width.pow((depth+1-level) as u32);
            // This creates for each parent node an empty vector
            let mut level_above: Vec<Vec<usize>> = vec![vec![]; data_level_above];
            // This is a hash set to only insert if the node is "new"
            let mut new_indices: HashSet<usize> = HashSet::new();
            /* The loop adds the index of the child that needs to be proven in the vector of the parent node
                Also the loop creates a vector for the indices of the parent node for the next layer*/
            for i in 0.. indexes.len(){
                level_above[indexes[i] / width].push(indexes[i]);
                new_indices.insert(indexes[i]/ width);
            }
            tree_path.push(level_above);
            indexes = new_indices.into_iter().collect();
                
        }
        // We need to add the root manually
        if depth != 0 {
            let mut node_root: Vec<usize> = Vec::new();
            for i in 0 .. width{
                let child  = &tree_path[tree_path.len()-1][i];
                if !child.is_empty(){
                    node_root.push(i);
                }
            }
            tree_path.push( vec![node_root]);
        }
        else {
            // If the tree has 1 layer, the "root" is just the commitment of all indices
            tree_path = vec![vec![index]];
        }
        tree_path.reverse();
        tree_path
    }
    

    // This function computes batch proofs, is also works if the NONE values are already deleted.
    pub fn verify (root: Commitment, mut tree_proofs: Vec<Option<ProofNode>>, width: usize, indices: Vec<usize>, depth: usize, data: Vec<Vec<u8>>, verifier_params: VerifierParams) -> bool {
        //tln!("start checking parameters");
        assert!(tree_proofs[0].is_some());

        // Check if the root is correct
        if root != tree_proofs[0].as_ref().unwrap().commitment {
            println!("Root commitment is not correct");
            return false;
        }

        tree_proofs.retain(|node| node.is_some());
        // The expected length
        let check_vector: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof(indices, width, depth);
        // To check the expected length we filter on non empty vectors. 
        let length = check_vector.iter()
            .flat_map(|layer| layer.iter()) 
            .filter(|node_vec| {
                !node_vec.is_empty()})
            .count();
        if tree_proofs.len() != length {
            println!("The tree proofs vector is not of the correct length");
            return false;
        }
        //println!("start making vector");
        // To find the commitment value easier, we dont save the ProofNodes but the commitments in the next vector
        let mut commitments_vector: Vec<Vec<u8>> = tree_proofs.iter().map(|proof_node|
            {
                let node = proof_node.as_ref().unwrap();
                Self::map_commitment_to_vec_u8(&node.commitment)
            }
        ).collect();
        data.iter().for_each(|d| commitments_vector.push(d.to_vec()));
        
        //println!("start verify");
        tree_proofs.par_iter().all(|proof_node| {
            if let Some(node) = proof_node{
                let b1 = Proof::same_commit_batch_verify(&node.proof, &verifier_params, &node.commitment, &node.indices, &node.values);
                // For simplicity we check if there is a commitment that matches
                let b2 = node.values.par_iter().all(|point| {
                    commitments_vector.par_iter().any(|n| n == point)
                });
                b1 & b2
            }
            else {
                true
            }
        });
        //println!("done verify");
        true
    }

    pub fn map_commitment_to_vec_u8(com: &Commitment) -> Vec<u8> {
        let mut old_commitment_bytes: Vec<u8> = vec![];
        com.serialize(&mut old_commitment_bytes, true).unwrap();
        old_commitment_bytes
        //Vec::new()
    }

    pub fn depth(&self) -> usize {
        self.nodes.len()
    }

    pub fn root_commitment(&self) -> Option<Commitment>{
        match self.nodes.is_empty() {
            true => None,
            false => {
                match self.nodes[0].is_empty(){
                    true => None,
                    false => Some(self.nodes[0][0].commitment.clone()),
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum VerkleTreeError {
    BuildError,
    ProofGenerateError,
    EmptyTree,
}
