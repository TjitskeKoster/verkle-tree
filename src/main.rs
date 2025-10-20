use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::time::Instant;

use std::fs::OpenOptions;
use std::io::Write;

use rand::Rng;
use rand::prelude::*;
use rayon::vec;

mod verkle_tree_point;
use verkle_tree_point::{VerkleTree as VerkleTree_point};


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



fn example (width:usize, input_len:usize, data: &Vec<Vec<u8>>) {
    //println!("create parameters");
    let (prover_params, verifier_params) =
        pointproofs::pairings::param::paramgen_from_seed("This is our Favourite very very long Seed", 0, width).unwrap();
    
    //println!("start making tree");
    let start = Instant::now();
    let tree: VerkleTree_point = VerkleTree_point::new(&data, width, prover_params).unwrap();
    let tree_test= start.elapsed();
   // println!("Tree is constructed");
    
    let indices: Vec<usize> = (0..=(input_len-1) )
        .choose_multiple(&mut thread_rng(),(input_len as f64 *(0.2))as usize);
    //println!("We'll start proving");
    let startproof = Instant::now();
    let proof = tree.proof(indices.clone(), &data);
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

    println!("tree create {:?}", tree_test.as_millis());
    println!("proof time {:?}", endproof_test.as_millis());
    println!("verify time {:?}", verify_test.as_millis());
}


fn main (){
    println!("Hello world");

    // println!("data length {}", datas.len());
    let width = 4;
    let input_len = usize::pow(2,10);

    // // Create synthetic data
    //let mut data: Vec<Vec<u8>> =Vec::new();
    // for _i in 0.. input_len{
    //     let v = rand::thread_rng().gen_range(0..=input_len*input_len) as u8;
    //     data.push(vec![v]);
    // }

    let data: Vec<Vec<u8>> = get_receiver_data(input_len); 
    println!("got data");

    for i in 0 .. 10 {
        example(width, input_len, &data);
    }
    // let width = 3;
    // let input_len = 9;
    // let data: Vec<Vec<u8>> = vec![vec![0], vec![1], vec![2], vec![3],vec![4], vec![5], vec![6], vec![7],vec![8]];
    // new(width, input_len, &data);

}