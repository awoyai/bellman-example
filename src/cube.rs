extern crate bellman;
extern crate bls12_381;
extern crate pairing;

use bellman::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
        Parameters,
    },
    SynthesisError, Variable,
};
use ff::{Field, PrimeField};
use rand::thread_rng;

use self::bellman::Circuit;
use bls12_381::{Bls12, Scalar};

pub struct CubeDemo<'a, S: PrimeField> {
    pub x: Option<S>,
    pub constants: &'a [S],
}

impl<'a, S: PrimeField> Circuit<S> for CubeDemo<'a, S> {
    fn synthesize<CS: bellman::ConstraintSystem<S>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        let x_val = self.x;
        let x: Variable = cs.alloc(|| "x", || x_val.ok_or(SynthesisError::AssignmentMissing))?;
        let x2_val = x_val.map(|e| e.square());
        let x2 = cs.alloc(|| "x*x", || x2_val.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce(|| "x2", |lc| lc + x, |lc| lc + x, |lc| lc + x2);

        let x3_val = x_val.map(|e| e.cube());
        let x3 = cs.alloc(
            || "x*x*x",
            || x3_val.ok_or(SynthesisError::AssignmentMissing),
        )?;
        cs.enforce(|| "x3", |lc| lc + x2, |lc| lc + x, |lc| lc + x3);
        let out = cs.alloc_input(
            || "out",
            || {
                let mut tmp = x3_val.unwrap();
                tmp.add_assign(&x_val.unwrap());
                tmp.add_assign(&ff::PrimeField::from_str_vartime("5").unwrap());
                Ok(tmp)
            },
        )?;
        cs.enforce(
            || "out",
            |lc| lc + x3 + x + (ff::PrimeField::from_str_vartime("5").unwrap(), CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + out,
        );
        Ok(())
    }
}

const MIMC_ROUNDS: usize = 322;

pub fn test_cube() {
    let mut rng = thread_rng();
    let constants = (0..MIMC_ROUNDS)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();
    let params: Parameters<Bls12> = {
        let c = CubeDemo {
            x: None,
            constants: &constants,
        };
        generate_random_parameters::<Bls12, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    let c: CubeDemo<Scalar> = CubeDemo {
        x: ff::PrimeField::from_str_vartime("3"),
        constants: &constants,
    };

    let proof = create_random_proof(c, &params, &mut rng);

    let b = verify_proof(
        &pvk,
        &proof.unwrap(),
        &[ff::PrimeField::from_str_vartime("35").unwrap()],
    );
    if let Ok(()) = b {
        println!("success!");
    } else {
        println!("err: {:?}", &b);
    }
}
