////////////////////////////////////////////////////////////////////////////////
//                                                                   
// Code for SIDH key exchange with optional public key compression          
// 
// (c) 2016 Microsoft Corporation. All rights reserved.         
//                                                                   
////////////////////////////////////////////////////////////////////////////////
//  
// References: 
//                                                            
// Efficient algorithms for supersingular isogeny Diffie-Hellman 
// Craig Costello, Patrick Longa, Michael Naehrig, CRYPTO 2016.         
//                                                                               
// Efficient compression of SIDH public keys
// Craig Costello, David Jao, Patrick Longa, Michael Naehrig, Joost Renes, 
// David Urbanik, EUROCRYPT 2017.     
// 
////////////////////////////////////////////////////////////////////////////////

This folder contains Magma scripts that implement SIDH key exchange as
described in the above two papers.

SIDH-parameters.mag
SIDH-field-arithmetic.mag
SIDH-curve-and-isogeny-arithmetic.mag
SIDH.mag
SIDH-pairings.mag
SIDH-pohlig-hellman.mag
SIDH-compression.mag
TestSIDH-kex.mag
Kummer_Weierstrass_equivalence.mag
optimalstrategies.mag

Running the test script 

> load "TestSIDH-kex.mag";

loads all the other files in the right order and provides two test functions.
The function

> kextest(n, simple);

will run and test n random instances of SIDH key exchange without public-key
compression. Setting the option simple:=false only runs the fast algorithms
via optimal strategies for isogeny computation and evaluation. Setting it to
simple:=true also runs the simple multiplication-based strategy and asserts
that the results obtained in both approaches are equal. The function 

> kextest_compress(n);

will run and test n random instances of SIDH key exchange including public-key
compression.


Running the script 

> load "Kummer_Weierstrass_equivalence.mag";

demonstrates the equivalence of computations on the Kummer variety with those 
on the Weierstrass model. 
Its purpose is to show that our computations give the same result as Magma's.
In particular, we work explicitly on the Kummer variety of supersingular
curves, almost entirely in projective space P^1, and using the Montgomery
x-coordinate. This script shows that this gives equivalent results to the
traditional way of computing isogenies: i.e., Velu's formulas on the affine
Weierstrass model, which are implemented in Magma's "IsogenyFromKernel"
function. 

WARNING: The script "Kummer_Weierstrass_equivalence.mag" will take several
minutes to execute fully, since Magma's "IsogenyFromKernel" function is slow 
in contrast to the projective Kummer computations. 

Finally, the script "optimalstrategies.mag" computes an optimal strategy for
traversing the isogeny tree based on the cost ratios of computing an
m-isogeny versus the multiplication-by-m map. It follows the discussion in the
paper and is based on the original method described by De Feo, Jao and Plut:
Towards quantum-resistant cryptosystems from supersingular elliptic curve
isogenies, J. Math. Crypt., 8(3):209-247, 2014.          

