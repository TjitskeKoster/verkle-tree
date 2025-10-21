use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::time::Instant;

use ark_bls12_381::{Fr as F, G1Affine};

use std::fs::OpenOptions;
use std::io::Write;

use rand::Rng;
use rand::prelude::*;
use rayon::vec;

mod verkle_tree_point;
use verkle_tree_point::{VerkleTree as VerkleTree_point};

mod verkle_tree;
use verkle_tree::{VerkleTree as VerkleTree_kzg};


//The following is to import data from a file in the root of the folder.

fn get_receiver_data (size_input: usize) -> Vec<Vec<u8>>{
    let file = File::open("Receiver.txt").expect("failed to open file");
    let reader = BufReader::new(file);

    let mut input:Vec<Vec<u8>> = Vec::with_capacity(size_input);
    for line in reader.lines() {
       let paswd = line.expect("failed to unrap line");
        if input.len()< size_input{
            //input.push(paswd.as_bytes().to_vec());
            input.push(paswd.into_bytes());
        }
        else {
            return input;
        }
    }
    input
}



fn example_pointproofs (width:usize, input_len:usize, data: &Vec<Vec<u8>>) {
    //println!("create parameters");
    let (prover_params, verifier_params) =
        pointproofs::pairings::param::paramgen_from_seed("This is our Favourite very very long Seed", 0, width).unwrap();
    
    //println!("start making tree");
    let start = Instant::now();
    let tree: VerkleTree_point = VerkleTree_point::new(data, width, prover_params).unwrap();
    let tree_test= start.elapsed();
   // println!("Tree is constructed");
    
    let indices: Vec<usize> = (0..=(input_len-1) )
        .choose_multiple(&mut thread_rng(),(input_len as f64 *(0.2))as usize);
    //println!("We'll start proving");
    let startproof = Instant::now();
    let proof = tree.proof(indices.clone(), data);
    let endproof_test= startproof.elapsed();
    //println!("We are done proving");

    //println!("Commitment");
    let root = tree.root_commitment().unwrap();
    let depth = tree.depth();
    //println!("commitment done");

    //println!("data to verify");

    let mut datas_verify: Vec<Vec<u8>> = Vec::new();
    for i in indices.clone() {
        datas_verify.push(data[i].clone());
    }

    //println!("start verify");
    let startverify = Instant::now();
    let b = VerkleTree_point::verify(root, proof.clone(), width, indices, depth, datas_verify, verifier_params);
    let verify_test= startverify.elapsed();
    //println!("end verify");

    println!("POINTPROOF tree create {:?}", tree_test.as_millis());
    println!("POINTPROOF proof time {:?}", endproof_test.as_millis());
    println!("POINTPROOF verify time {:?}", verify_test.as_millis());
}



fn example_kzg (width:usize, input_len:usize, data: &Vec<F>) {
    //println!("start making tree");
    //println!("data {:?}", data);
    let start = Instant::now();
    let tree: VerkleTree_kzg = VerkleTree_kzg::new(data, width).unwrap();
    let tree_test= start.elapsed();
   // println!("Tree is constructed");
    
    let indices: Vec<usize> = (0..=(input_len-1) )
        .choose_multiple(&mut thread_rng(),(input_len as f64 *(0.2))as usize);
    //let indices = vec![0];
    //println!("We'll start proving");
    let startproof = Instant::now();
    let proof = tree.proof(indices.clone(), data);
    let endproof_test= startproof.elapsed();
    //println!("We are done proving");

    //println!("Commitment");
    let root = tree.root_commitment().unwrap();
    let depth = tree.depth();
    //println!("commitment done");

    //println!("data to verify");

    let mut datas_verify: Vec<F> = Vec::new();
    for i in indices.clone() {
        datas_verify.push(data[i].clone());
    }

    //println!("start verify");
    let startverify = Instant::now();
    let b = VerkleTree_kzg::verify(root, proof.clone(), width, indices, depth, datas_verify);
    let verify_test= startverify.elapsed();
    //println!("end verify");

    println!("KZG tree create {:?}", tree_test.as_millis());
    println!("KZG proof time {:?}", endproof_test.as_millis());
    println!("KZG verify time {:?}", verify_test.as_millis());
}


fn main (){
    println!("Hello world");

    // let datas_kzg = vec![F::from(15), F::from(23), F::from(37), F::from(48), F::from(52), F::from(66), F::from(73), F::from(84), F::from(91), F::from(104), F::from(113), F::from(128), F::from(137), F::from(141), F::from(155), F::from(164)];

    // let width = 4;

    // example_kzg(width, datas_kzg.len(), &datas_kzg);

    // println!("data length {}", datas.len());
    let width = 4;
    let input_len = usize::pow(2,10);

    // Create synthetic data
    let mut data: Vec<Vec<u8>> =Vec::new();
    for _i in 0.. input_len{
        let v = rand::thread_rng().gen_range(0..=input_len*input_len) as u8;
        data.push(vec![v]);
    }

    // Create synthetic data kzg
    let mut data_kzg: Vec<F> =Vec::new();
    for _i in 0.. input_len{
        let v = rand::thread_rng().gen_range(0..=input_len*input_len) as u8;
        data_kzg.push(F::from(v));
    }

    let data: Vec<Vec<u8>> = get_receiver_data(input_len); 
    println!("got data");

    for i in 0 .. 10 {
        example_pointproofs(width, input_len, &data);
        example_kzg(width, input_len, &data_kzg);
    }

}