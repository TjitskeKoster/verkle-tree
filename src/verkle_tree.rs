use std::{collections::HashSet, vec};

use ark_bls12_381::{Fr as F, G1Affine};
use ark_ec:: AffineRepr;
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use kzg_commitment::ProofError;
use num_bigint::BigUint;

use pointproofs::pairings::Commitment;
use rayon::prelude::*;

pub struct VerkleTree {
    nodes: Vec<Vec<VerkleNode>>,
    width: usize,
    kzg: KZGCommitment,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    polynomial: DensePolynomial<F>,
    children: bool,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub proofs: Vec<ProofNode>,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub commitment: G1Affine,
    pub proof: G1Affine,
    pub point: Vec<(F, F)>,
}

impl VerkleTree {
    pub fn new(datas: &Vec<F>, width: usize) -> Result<Self, VerkleTreeError> {
        let kzg = KZGCommitment::new(width);
        Self::build_tree(kzg, datas, width)
    }

    fn build_tree(kzg: KZGCommitment, datas: &Vec<F>, width: usize) -> Result<VerkleTree, VerkleTreeError> {
        if datas.is_empty() {
          return Err(VerkleTreeError::BuildError);
        }
        assert!(datas.len().is_multiple_of(width), "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number otherwise security can not be guaranteed");
        // We build the tree layer per layer
        //println!("Start making the first layer with no children");
        let mut layer = Self::create_leaf_nodes(&kzg, datas, width);
        // println!("first layer {:?}", layer);
        //println!("first layer is constructed");
        let mut tree: Vec<Vec<VerkleNode>> = Vec::new();
        tree.push(layer.clone());
        while layer.len() > 1 {
            layer = Self::build_layer(&kzg, &layer, width);
            tree.push(layer.clone());
            //println!("next layer is constructed");
        }
        // to get the root as first index.
        tree.reverse();
        // for layer in tree.clone() {
        //     println!(" ");
        //     println!("{:?}", layer);
        // }
        //tree = Self::add_incides(tree);
        Ok(VerkleTree {
            nodes: tree,
            width,
            kzg,
        })
    }
    
    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &[F], width: usize) -> Vec<VerkleNode> {
        datas
            .par_chunks(width)
            .map(|chunk| {
                let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                    children: false,
                }
            })
            .collect()
    }

    fn build_layer (kzg: &KZGCommitment, nodes: &[VerkleNode], width: usize, ) -> Vec<VerkleNode>{
        nodes
        .par_chunks(width)
            .map(|chunk| {
                let vector_commitment_mapping = chunk
                    .par_iter()
                    .map(|node| Self::map_commitment_to_field(&node.commitment))
                    .collect();
                let polynomial = KZGCommitment::vector_to_polynomial(&vector_commitment_mapping);
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                    children: true,
                }
            })
            .collect()
    }

    pub fn proof(&self, index:Vec<usize>, data: &[F]) -> Vec<Option<ProofNode>> {
        assert!(data.len().is_multiple_of(self.width), "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");
        assert!(!index.is_empty(), "Please give a non empty index");
        let width = self.width;
        // The following line creates a vector, on each index is a vector which incidates which children nodes need to be proven
        //println!("create index for proof");
        let index_for_proof = Self::create_index_for_proof(index, width, self.depth());
        //println!("index proof {:?}", index_for_proof);
        //println!("done creating indices");
        let tree: Vec<Vec<VerkleNode>> = self.nodes.clone();

        let flattened_tree: Vec<(usize, usize, &VerkleNode)> = tree.iter()
            .enumerate()
            .flat_map(|(layer_index,layer)|{
                layer.iter().enumerate().map(move |(node_index, node)| (layer_index, node_index, node))
            }).collect();
        
        flattened_tree.par_iter().map(|(layer_index, node_index, node)|{
            let mut points = Vec::new();
            let indices: &Vec<usize> = &index_for_proof[*layer_index][*node_index];
            // let mut proof_indices: Vec<usize> = Vec::new();
            //     for index in indices{
            //         proof_indices.push(index % width);
            //     }
            if indices.is_empty() {
                None
            }
            else if node.children {
                for ind in indices {
                    let com = &tree[layer_index+1][*ind].commitment;
                    let child_commitment = Self::map_commitment_to_field(&com);
                    let index = *ind % width;
                    //println!("index {}", ind);
                    points.push((F::from((index) as u32),child_commitment));
                }
                Some(self.find_proof_node(node, points).expect("failed to generate proof for node"))
            }
            else {
                // no children so values from the data
                for ind in indices {
                    //println!("index data {}, {:?}", ind, data[*ind]);
                    let index = *ind % width;
                    points.push((F::from(index as u32), data[*ind]));
                }
                //println!("poly {:?}", node.polynomial);
                Some(self.find_proof_node(node,  points).expect("failed to generate proof for node"))
                }
        }).collect()
        
    }

    //     let proofs: Vec<Option<ProofNode>> = (0.. index_for_proof.len())
    //     .into_par_iter()
    //     .map(|ind| {
    //         if index_for_proof[ind]!= vec![]  {
    //             let path = Self::path_to_child(ind, width);

    //             let node: VerkleNode = Self::find_commitment_node(self, path);
    //             let index_first_child: usize =
    //                 if node.children.is_none(){
    //                     let index_first_child_data: usize = 
    //                         if width == 2 {
    //                             usize::pow(width, (depth+1).try_into().unwrap())/(width-1) -1
    //                         }
    //                         else {
    //                             usize::pow(width, (depth+1).try_into().unwrap())/(width-1)
    //                         };
    //                     width*ind +1 - index_first_child_data
    //                 }
    //                 else {
    //                     width*ind +1
    //                 };
    //             let proof_of_node = self.find_proof_node(node,  index_for_proof[ind].clone(), data, index_first_child).expect("failed to generate proof for node");
    //             Some(proof_of_node)
    //         }
    //         else {
    //             None
    //         }
    //     }).collect();
    //     proofs
    // }

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
                println!("tree path lengt {} dept {} i {}", tree_path.len(), depth, i); 
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

    fn find_proof_node (&self, node: &VerkleNode, points:Vec<(F,F)>) ->  Result<ProofNode, VerkleTreeError>  {

        let proof: Result<G1Affine, ProofError> = self.kzg.generate_proof(&node.polynomial, &points);
        
        match proof {
            Ok(proof) => {
                let proof_node = ProofNode {
                    commitment: node.commitment,
                    proof,
                    point: points,
                };
                Ok(proof_node)
            }
            Err(_) => Err(VerkleTreeError::ProofGenerateError),
        }
    }

    // This function computes batch proofs, is also works if the NONE values are already deleted.
    pub fn verify (root: G1Affine, mut tree_proofs: Vec<Option<ProofNode>>, width: usize, indices: Vec<usize>, depth: usize, data: Vec<F>) -> bool {
        assert!(tree_proofs[0].is_some());

        // Check if the root is correct
        if root != tree_proofs[0].as_ref().unwrap().commitment {
            println!("Root commitment is not correct");
            return false;
        }

        // Check if the proofs are of the correct size, also works if NONE values were already deleted
        tree_proofs.retain(|node| node.is_some());
        // The expected length
        let check_vector: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof(indices, width, depth);
        let length = check_vector.iter()
            .flat_map(|layer| layer.iter()) 
            .filter(|node_vec| {
                !node_vec.is_empty()})
            .count();
        if tree_proofs.len() != length {
            println!("The tree proofs vector is not of the correct length");
            println!(" lengt {}, {}", length, tree_proofs.len());
            return false;
        }
        // To find the commitment value easier, we dont save the ProofNodes but the commitments in the next vector
        let mut commitments_vector: Vec<F> = tree_proofs.iter().map(|proof_node|
            {
                let node = proof_node.as_ref().unwrap();
                Self::map_commitment_to_field(&node.commitment)
            }
        ).collect();
        data.iter().for_each(|d| commitments_vector.push(*d));
        
        let kzg = KZGCommitment::new(width + 1);
        tree_proofs.par_iter().all(|proof_node| {
            if let Some(node) = proof_node{
                let b1 = kzg.verify_proof(&node.commitment, &node.point, &node.proof);
                // For simplicity we check if there is a commitment that matches
                let b2 = node.point.par_iter().all(|point| {
                    commitments_vector.iter().any(|n| *n == point.1)
                });
                b1 & b2
            }
            else {
                true
            }
        });
        true
    }

    fn map_commitment_to_field(g1_point: &G1Affine) -> F {
        let fq_value = g1_point.x().expect("its the x value") + g1_point.y().expect("its the y value");
        let fq_bigint: BigUint = fq_value.into_bigint().into();
        F::from_le_bytes_mod_order(&fq_bigint.to_bytes_le())
    }

    pub fn depth(&self) -> usize {
        self.nodes.len()
    }

    pub fn root_commitment(&self) -> Option<G1Affine> {
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
