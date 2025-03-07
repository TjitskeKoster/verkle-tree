use std::{collections::HashSet, time::Instant, vec};

use ark_bls12_381::{Fr as F, G1Affine};
use ark_ec::AffineRepr;
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use num_bigint::BigUint;

use recursive::recursive;

use rayon::prelude::*;
use rayon::scope;
//use rayon::ThreadPoolBuilder;
use std::sync::{Arc, Mutex};

pub struct VerkleTree {
    root: Option<VerkleNode>,
    width: usize,
    kzg: KZGCommitment,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    polynomial: DensePolynomial<F>,
    children: Option<Vec<VerkleNode>>,
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
        if datas.len() == 0 {
          return Err(VerkleTreeError::BuildError);
        }
        if datas.len() <= width {
            let polynomial = KZGCommitment::vector_to_polynomial(datas);
            let commitment = kzg.commit_polynomial(&polynomial);
            return Ok(VerkleTree {
                root: Some(VerkleNode {
                    commitment,
                    polynomial,
                    children: None,
                }),
                width,
                kzg,
            });
        }
        let leaf_nodes = Self::create_leaf_nodes(&kzg, datas, width);
        // for i in 0.. leaf_nodes.len(){
        //     println!("leaf node {} of build_tree {:?}", i, leaf_nodes[i]);
        // }
        let root = Self::build_tree_recursively(&kzg, &leaf_nodes, width);

        Ok(VerkleTree {
            root: Some(root),
            width,
            kzg,
        })
    }

    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> Vec<VerkleNode> {
        datas
            .chunks(width)
            .map(|chunk| {
                let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                    children: None,
                }
            })
            .collect()
    }

    fn build_from_nodes(
        kzg: &KZGCommitment,
        nodes: &Vec<VerkleNode>,
        width: usize,
    ) -> Vec<VerkleNode> {
        nodes
            .chunks(width)
            .map(|chunk| {
                let vector_commitment_mapping = chunk
                    .into_iter()
                    .map(|node| Self::map_commitment_to_field(&node.commitment))
                    .collect();
                let polynomial = KZGCommitment::vector_to_polynomial(&vector_commitment_mapping);
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                    children: Some(chunk.to_vec()),
                }
            })
            .collect()
    }

    fn build_tree_recursively(
        kzg: &KZGCommitment,
        nodes: &Vec<VerkleNode>,
        width: usize,
    ) -> VerkleNode {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }
        let next_level = Self::build_from_nodes(kzg, nodes, width);
        Self::build_tree_recursively(kzg, &next_level, width)
    }

    pub fn generate_proof(&self, index: usize, data: &F) -> Result<VerkleProof, VerkleTreeError> {
        let mut node_positions = Vec::<usize>::new();
        let mut value_positions = Vec::<usize>::new();

        let mut current_node = index / self.width;
        let mut current_position = index % self.width;

        let depth = self.depth();

        for _ in 0..=depth {
            node_positions.push(current_node);
            value_positions.push(current_position);

            current_position = current_node % self.width;
            current_node = current_node / self.width;
        }
        node_positions.reverse();
        value_positions.reverse();

        let mut current_node = self.root.clone().unwrap();

        let mut proofs = Vec::<ProofNode>::new();
        for (i, &_node_position) in node_positions.iter().enumerate() {
            let current_commitment = current_node.commitment.clone();
            // assert_eq!(current_commitment, self.root().unwrap());
            let current_polynomial = current_node.polynomial.clone();
            let node_to_prove_position = value_positions[i];
            let data_to_prove = if let Some(children) = current_node.children {
                let next_node = children[node_to_prove_position].clone();
                let next_node_commitment = next_node.commitment;
                current_node = next_node;
                Self::map_commitment_to_field(&next_node_commitment)
            } else {
                *data
            };

            let points = vec![(F::from(node_to_prove_position as u32), data_to_prove)];
            let proof = self.kzg.generate_proof(&current_polynomial, &points);

            match proof {
                Ok(proof) => {
                    proofs.push(ProofNode {
                        commitment: current_commitment,
                        proof: proof,
                        point: points,
                    });
                }
                Err(_) => return Err(VerkleTreeError::ProofGenerateError),
            }
        }

        Ok(VerkleProof { proofs })
    }

    pub fn create_index_for_proof(index: Vec<usize>, width: usize, depth: usize, tree_proofs: &mut Vec<Vec<Vec<ProofNode>>>) -> Vec<Vec<Vec<usize>>> {
        /* This creates a vector of the form:
            [[[2, 0]], [[1, 2], [], [0]]] 
            It has lenght 2, this indicates that there are 2 layers in the tree
            The root is implicit indicated, on place 0 there is [[2,0]] which indicates that 
            children 0 and 2 of the root need to be proven.
            The next layer, there is [[1, 2], [], [0]] which indicates that
            for the first child [1,2] need to be proven, for the next child nothing needs to be proven
            and for the last child only index [0] needs to be proven.
         */
        let mut tree_path: Vec<Vec<Vec<usize>>>  = Vec::new();
        let mut indexes = index.clone();
        for level in 1.. (depth+1){
            let data_level_above = width.pow((depth+1-level) as u32);
            // This creates for each parent node an empty vector
            let mut level_above: Vec<Vec<usize>> = vec![vec![]; data_level_above];
            let level_above_proofs: Vec<Vec<ProofNode>>= vec![vec![]; data_level_above];
            let mut new_indices: HashSet<usize> = HashSet::new();
            /* The loop adds the index of the child that needs to be proven in the vector of the parent node
                This is done modulus the width of the tree. 
                Also the loop creates a vector for the indices of the parent node for the next layer*/
            for i in 0.. indexes.len(){
                level_above[indexes[i] / width].push(indexes[i]% width);
                new_indices.insert(indexes[i]/ width);
            }
            tree_path.push(level_above);
            tree_proofs.push(level_above_proofs);
            indexes = new_indices.into_iter().collect();
             
        }
        // We need to add the root manually
        let mut node_root: Vec<usize> = Vec::new();
        for child in 0.. width{
            if !tree_path[tree_path.len()-1][child].is_empty(){
                node_root.push(child);
            }
        }
        tree_path.push(vec![node_root]);
        tree_proofs.push(vec![vec![]]);
        tree_path.reverse();
        tree_proofs.reverse();
        tree_path
    }

    #[recursive]
    fn batch_proof_layer_vector_old (&self, current_node: VerkleNode, node_ind: usize, tree_path: Vec<Vec<Vec<usize>>>, data: &Vec<F>, tree_proofs: &mut Vec<Vec<Vec<ProofNode>>>) -> Result<ProofNode, VerkleTreeError>  {

        let index_to_prove: &Vec<usize> = &tree_path[0][node_ind];
        let mut points: Vec<(F,F)>= Vec::new();
        let original_lenght_layer_0: usize;
        if 1 < tree_path.len() {
            original_lenght_layer_0 = tree_path[1].len()/ self.width;
        }
        else {
            original_lenght_layer_0 = data.len()/ self.width;
        }
        let new = tree_path[0].len();
        let index_node_in_layer = original_lenght_layer_0-new+ node_ind;
        let index_first_child: usize = index_node_in_layer*self.width;
        //If the node has children we continue down the tree, if the none has no children we go to the leaf case
        if let Some(children)= current_node.children{
            for ind in index_to_prove{
                // Collect the children and their commitment value
                let next_node: VerkleNode = children[*ind].clone();
                let next_node_commitment: F = Self::map_commitment_to_field(&next_node.commitment);
                // We need to batch proof these later
                points.push((F::from(*ind as u32), next_node_commitment));
                // We need to proof some children of the children nodes as well. Tey are in the next layer, so we pop the first element.
                let mut tree_path_next_layer: Vec<Vec<Vec<usize>>> = tree_path.clone().drain(1..).collect();
                
                /* The first vector of the next layer starts at the beginning of the tree.
                We want it to start at the index we are interested in */
                tree_path_next_layer[0] = tree_path_next_layer[0].clone().drain(index_first_child ..).collect();
                /* To find the right index of the leaf later we keep the counter. 
                This indicates the least index of the leaves under the current node */
                //let ind_leaf: usize = index_leaf+ node_ind* usize::pow(self.width, tree_path.len() as u32);
                self.batch_proof_layer_vector_old(next_node, *ind, tree_path_next_layer, data, tree_proofs).expect("failed tree");
            }
        }
        else {
            // leaf case
            for ind in index_to_prove{
                let index_data: usize = index_first_child + ind;
                points.push((F::from(*ind as u32), data[index_data]));
            }
        }
        let current_polynomial = current_node.polynomial.clone();
        let proof = self.kzg.generate_proof(&current_polynomial, &points);
        let current_commitment = current_node.commitment.clone();
        let mut outp: Vec<ProofNode> = Vec::new();
        match proof {
            Ok(proof) => {
                outp.push(ProofNode {
                    commitment: current_commitment,
                    proof: proof,
                    point: points,
                });
            }
            Err(_) => return Err(VerkleTreeError::ProofGenerateError),
            
        }
        tree_proofs[self.depth()-(tree_path.len()-1)][index_node_in_layer].push(outp[0].clone());
        Ok(outp[0].clone())
    }

    pub fn generate_batch_proof_old (&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Vec<Vec<ProofNode>>> {
        //println!("depth {}", depth);
        let mut tree_proofs: Vec<Vec<Vec<ProofNode>>>  = Vec::new();
        let tree_path: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof(index, self.width, self.depth(), &mut tree_proofs);

        let current_node = self.root.clone().unwrap();
        //self.batch_proof_layer(current_node, 0, tree_path, proofs, data, 0)
        self.batch_proof_layer_vector_old(current_node, 0, tree_path, data, &mut tree_proofs).expect("failed to make batch proof");
        tree_proofs
    }

    // #[recursive]
    // fn batch_proof_layer_vector (&self, current_node: VerkleNode,
    //     node_ind: usize, tree_path: Vec<Vec<Vec<usize>>>,
    //     data: &Vec<F>, tree_proofs: Arc<Mutex<Vec<Vec<Vec<ProofNode>>>>>)
    //     -> Result<ProofNode, VerkleTreeError>  {

    //     /*  The three path contains information about what children to prove
    //         The first index contains info about the nodes to the right of the current node
    //         The next indices of the path contain information about the next layers
    //          */ 
    //     let index_to_prove: &Vec<usize> = &tree_path[0][node_ind];
    //     /*  The index of the current node in the layer can be found
    //         by the difference of the original length of the layer and the 
    //         current length of the layer. Together with the index of the node. 
    //     */
    //     let original_lenght_layer_0: usize;
    //     if 1 < tree_path.len() {
    //         original_lenght_layer_0 = tree_path[1].len()/ self.width;
    //     }
    //     else {
    //         original_lenght_layer_0 = data.len()/ self.width;
    //     }
    //     let new = tree_path[0].len();
    //     let index_node_in_layer = original_lenght_layer_0-new+ node_ind;
    //     let index_first_child: usize = index_node_in_layer*self.width;

    //     let points = Arc::new(Mutex::new(Vec::new()));
    //     //let mut points: Vec<(F,F)>= Vec::new();
    //     //If the node has children we continue down the tree, if the none has no children we go to the leaf case
    //     if let Some(children)= current_node.children{
    //         //for ind in index_to_prove{
    //         index_to_prove.par_iter().for_each(|ind| {
    //             // Collect the children and their commitment value
    //             let next_node: VerkleNode = children[*ind].clone();
    //             let next_node_commitment: F = Self::map_commitment_to_field(&next_node.commitment);
    //             // We need to batch proof these later
    //             {
    //                 let mut locked_points = points.lock().unwrap();
    //                 locked_points.push((F::from(*ind as u32), next_node_commitment));
    //             }
    //             // We need to proof some children of the children nodes as well. Tey are in the next layer, so we pop the first element.
    //             let mut tree_path_next_layer: Vec<Vec<Vec<usize>>> = tree_path.clone().drain(1..).collect();
                
    //             /* The first vector of the next layer starts at the beginning of the tree.
    //             We want it to start at the index we are interested in */
    //             tree_path_next_layer[0] = tree_path_next_layer[0].clone().drain(index_first_child ..).collect();
    //             /* To find the right index of the leaf later we keep the counter. 
    //             This indicates the least index of the leaves under the current node */
    //             //let ind_leaf: usize = index_leaf+ node_ind* usize::pow(self.width, tree_path.len() as u32);

    //             //(F::from(*ind as u32), next_node_commitment)
    //             self.batch_proof_layer_vector(next_node, *ind, tree_path_next_layer, data, Arc::clone(&tree_proofs)).expect("failed tree");
    //         });
    //     }
    //     else {
    //         // leaf case
    //         index_to_prove.par_iter().for_each(|ind|{ 
    //             let index_data: usize = index_first_child + ind;
    //             let mut locked_points = points.lock().unwrap();
    //             locked_points.push((F::from(*ind as u32), data[index_data]));
    //         });
    //     }

    //     // Convert Arc<Mutex<Vec<T>>> back to Vec<T>
    //     let points_vector: Vec<(F,F)> = Arc::try_unwrap(points)
    //     .unwrap()
    //     .into_inner()
    //     .unwrap();

    //     let current_polynomial = current_node.polynomial.clone();
    //     let proof = self.kzg.generate_proof(&current_polynomial, &points_vector);
    //     let current_commitment = current_node.commitment.clone();
    //     let mut outp: Vec<ProofNode> = Vec::new();
    //     match proof {
    //         Ok(proof) => {
    //             outp.push(ProofNode {
    //                 commitment: current_commitment,
    //                 proof: proof,
    //                 point: points_vector,
    //             });
    //         }
    //         Err(_) => return Err(VerkleTreeError::ProofGenerateError),
            
    //     }
    //     {
    //         let mut locked_tree_proofs = tree_proofs.lock().unwrap();
    //         locked_tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].push(outp[0].clone());
    //     }
    //     //tree_proofs[self.depth()-(tree_path.len()-1)][index_node_in_layer].push(outp[0].clone());
    //     //println!("tree proofs {:?}", tree_proofs);
    //     Ok(outp[0].clone())
    // }

    #[recursive]
    fn batch_proof_layer_vector(
        &self,
        current_node: VerkleNode,
        node_ind: usize,
        tree_path: Vec<Vec<Vec<usize>>>,
        data: &Vec<F>,
        //tree_proofs: Arc<Mutex<Vec<Vec<Vec<ProofNode>>>>>)
        tree_proofs: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>>)
        -> Result<ProofNode, VerkleTreeError> 
    {
        let index_to_prove: &Vec<usize> = &tree_path[0][node_ind];

        let original_length_layer_0 = if tree_path.len() > 1 {
            tree_path[1].len() / self.width
        } else {
            data.len() / self.width
        };
        let new = tree_path[0].len();
        let index_node_in_layer = original_length_layer_0 - new + node_ind;
        let index_first_child = index_node_in_layer * self.width;

        // Use a thread-local vector to avoid lock contention
        let mut local_points = Vec::new();

        if let Some(children) = current_node.children {
            // Parallelize processing of child nodes
            scope(|s| {
                for &ind in index_to_prove {
                    let next_node = children[ind].clone();
                    let next_node_commitment = Self::map_commitment_to_field(&next_node.commitment);
                    
                    local_points.push((F::from(ind as u32), next_node_commitment));
    
                    let mut tree_path_next_layer: Vec<Vec<Vec<usize>>> = tree_path[1..].to_vec();
                    tree_path_next_layer[0] = tree_path_next_layer[0][index_first_child..].to_vec();
    
                    let tree_proofs_clone = Arc::clone(&tree_proofs);
                    s.spawn(move |_| {
                        self.batch_proof_layer_vector(
                            next_node, ind, tree_path_next_layer, data, tree_proofs_clone
                        ).expect("failed tree");
                    });
                }
            });

            // // Wait for all spawned threads to complete
            // for handle in child_proofs {
            //     handle.join().unwrap();
            // }
        } else {
            // Leaf case: process leaf proofs in parallel
            local_points.extend(
                index_to_prove
                    .par_iter()
                    .map(|ind| {
                        let index_data = index_first_child + ind;
                        (F::from(*ind as u32), data[index_data])
                    })
                    .collect::<Vec<_>>(),
            );
        }

        let current_polynomial = current_node.polynomial.clone();
        let proof = self.kzg.generate_proof(&current_polynomial, &local_points);
        let current_commitment = current_node.commitment.clone();

        if let Ok(proof) = proof {
            let proof_node = ProofNode {
                commitment: current_commitment,
                proof,
                point: local_points,
            };

            // Update tree_proofs safely in parallel
            let mut locked_slot = tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].lock().unwrap();
            locked_slot.push(proof_node.clone());

            // let mut locked_tree_proofs = tree_proofs.lock().unwrap();
            // locked_tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].push(proof_node.clone());

            return Ok(proof_node);
        } else {
            return Err(VerkleTreeError::ProofGenerateError);
        }
}


    pub fn generate_batch_proof (&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Vec<Vec<ProofNode>>> {
        //println!("depth {}", depth);
        assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");

        let mut tree_proofs: Vec<Vec<Vec<ProofNode>>>  = Vec::new();
        //let startpath = Instant::now();
        //let tree_proofs: Arc<Mutex<Vec<Vec<Vec<ProofNode>>>>> = Arc::new(Mutex::new(Vec::new()));
        let tree_path: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof(index, self.width, self.depth(), &mut tree_proofs);
        //let endpath = startpath.elapsed();
        //println!("Made the path to prove {:0.3?}", endpath);

        let tree_proofs_arc: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>> = Arc::new(
            tree_proofs
                .into_iter()
                .map(|layer| {
                    layer
                        .into_iter()
                        .map(|slot| Mutex::new(slot)) // Wrap each slot in a Mutex
                        .collect()
                })
                .collect()
        );
        
        //let tree_proofs_arc: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>> = Arc::new(Mutex::new(tree_proofs));
        let current_node = self.root.clone().unwrap();
        //self.batch_proof_layer(current_node, 0, tree_path, proofs, data, 0)
        //let startproof = Instant::now();
        self.batch_proof_layer_vector(current_node, 0, tree_path, data, tree_proofs_arc.clone()).expect("failed to make batch proof");
        let tree_proofs_vector: Vec<Vec<Vec<ProofNode>>> = tree_proofs_arc
        .iter()
        .map(|layer| {
            layer
                .iter()
                .map(|slot| slot.lock().unwrap().clone()) // Lock each slot and clone the inner Vec<ProofNode>
                .collect()
        })
        .collect();
        // let tree_proofs_vector:  Vec<Vec<Vec<ProofNode>>> = Arc::try_unwrap(tree_proofs_arc)
        // .unwrap()
        // .into_inner()
        // .unwrap();
        //println!("Made all proves {:0.3?}", startproof.elapsed());
        tree_proofs_vector
    }


    pub fn verify_proof(root: G1Affine, verkle_proof: &VerkleProof, width: usize) -> bool {
        let proof_root = verkle_proof.proofs[0].commitment;
        if proof_root != root {
            return false;
        }
        let kzg = KZGCommitment::new(width+1);
        let verkle_proofs = verkle_proof.proofs.clone();
        for proof in verkle_proofs {
            if !kzg.verify_proof(&proof.commitment, &proof.point, &proof.proof){
                return  false;
            }
        }
        true
    }

    pub fn batch_verify_classic (root: G1Affine, tree_proofs: Vec<Vec<Vec<ProofNode>>>, width: usize)  -> bool{
        if root!= tree_proofs[0][0][0].commitment{
            return false;
        }
        let kzg = KZGCommitment::new(width+1);
        for i in 0 .. tree_proofs.len(){
            for j in 0.. tree_proofs[i].len(){
                for proof in tree_proofs[i][j].clone(){
                    if !kzg.verify_proof(&proof.commitment, &proof.point, &proof.proof){
                        return  false;
                    }
                }
            }
        }
        true 

    }

    pub fn verify_batch_proof(root: G1Affine, tree_proofs: Vec<Vec<Vec<ProofNode>>>, width: usize) -> bool {
        if root != tree_proofs[0][0][0].commitment {
            return false;
        }
        // .all makes it such that if any verification fails, it stops immediately and returns false
        let kzg = KZGCommitment::new(width + 1);
        let _ = Instant::now();
        tree_proofs.par_iter().all(|layer| {
            layer.par_iter().all(|node| {
                node.par_iter().all(|proof| {
                    kzg.verify_proof(&proof.commitment, &proof.point, &proof.proof)
                })
            })
        });
        //println!("end verify {:0.3?}", startverify.elapsed());
        true
    }



    fn map_commitment_to_field(g1_point: &G1Affine) -> F {
        let fq_value = g1_point.x().unwrap() + g1_point.y().unwrap();
        let fq_bigint: BigUint = fq_value.into_bigint().into();
        F::from_le_bytes_mod_order(&fq_bigint.to_bytes_le())
    }

    pub fn depth(&self) -> usize {
        let mut depth = 0;

        let mut current_node = self.root.clone().unwrap(); // TODO: error handling
        while current_node.children.is_some() {
            depth += 1;
            current_node = current_node.children.unwrap()[0].clone();
        }
        depth
    }

    pub fn root_commitment(&self) -> Option<G1Affine> {
        match &self.root {
            None => None,
            Some(verkle_node) => Some(verkle_node.commitment),
        }
    }
}

#[derive(Debug)]
pub enum VerkleTreeError {
    BuildError,
    ProofGenerateError,
    EmptyTree,
}
