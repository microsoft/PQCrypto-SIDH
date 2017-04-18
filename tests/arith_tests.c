/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: testing code for field arithmetic, elliptic curve and isogeny functions
*
*********************************************************************************************/

#include "../SIDH.h"
#include "../SIDH_internal.h"
#include "test_extras.h"
#include <malloc.h>
#include <stdio.h>

extern const unsigned int splits_Alice[MAX_Alice];
extern const unsigned int splits_Bob[MAX_Bob];


// Benchmark and test parameters  
#if defined(GENERIC_IMPLEMENTATION) 
    #define BENCH_LOOPS           100       // Number of iterations per bench
    #define SMALL_BENCH_LOOPS     100       // Number of iterations per bench
    #define TEST_LOOPS             10       // Number of iterations per test
    #define ECPT_TEST_LOOPS         5       // Number of iterations per EC point generation test
    #define ECPAIR_TEST_LOOPS       5       // Number of iterations per pairing test
    #define ECPH_TEST_LOOPS        10       // Number of iterations per Pohlig-Hellman test
    #define COMP_TEST_LOOPS         5       // Number of iterations per Pohlig-Hellman test
#else
    #define BENCH_LOOPS        100000 
    #define SMALL_BENCH_LOOPS   10000       
    #define TEST_LOOPS            100       
    #define ECPT_TEST_LOOPS        20       
    #define ECPAIR_TEST_LOOPS      20       
    #define ECPH_TEST_LOOPS        50       
    #define COMP_TEST_LOOPS        10       
#endif


bool fp_test()
{ // Tests for the field arithmetic
    bool OK = true;
    int n, passed;
    felm_t a, b, c, d, e, f, ma, mb, mc, md, me, mf;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Testing field arithmetic over GF(p751): \n\n"); 

    // Field addition over the prime p751
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fprandom751_test(a); fprandom751_test(b); fprandom751_test(c); fprandom751_test(d); fprandom751_test(e); fprandom751_test(f); 

        fpadd751(a, b, d); fpadd751(d, c, e);                 // e = (a+b)+c
        fpadd751(b, c, d); fpadd751(d, a, f);                 // f = a+(b+c)
        fpcorrection751(e);
        fpcorrection751(f);
        if (fpcompare751(e,f)!=0) { passed=0; break; }

        fpadd751(a, b, d);                                     // d = a+b 
        fpadd751(b, a, e);                                     // e = b+a
        fpcorrection751(d);
        fpcorrection751(e);
        if (fpcompare751(d,e)!=0) { passed=0; break; }

        fpzero751(b);
        fpadd751(a, b, d);                                     // d = a+0 
        if (fpcompare751(a,d)!=0) { passed=0; break; }
        
        fpzero751(b);
        fpcopy751(a, d);     
        fpneg751(d);                      
        fpadd751(a, d, e);                                     // e = a+(-a)
        fpcorrection751(e);
        if (fpcompare751(e,b)!=0) { passed=0; break; }
    }
    if (passed==1) printf("  GF(p) addition tests ............................................ PASSED");
    else { printf("  GF(p) addition tests... FAILED"); printf("\n"); return false; }
    printf("\n");

    // Field subtraction over the prime p751
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fprandom751_test(a); fprandom751_test(b); fprandom751_test(c); fprandom751_test(d); fprandom751_test(e); fprandom751_test(f); 

        fpsub751(a, b, d); fpsub751(d, c, e);                 // e = (a-b)-c
        fpadd751(b, c, d); fpsub751(a, d, f);                 // f = a-(b+c)
        fpcorrection751(e);
        fpcorrection751(f);
        if (fpcompare751(e,f)!=0) { passed=0; break; }

        fpsub751(a, b, d);                                     // d = a-b 
        fpsub751(b, a, e);                                         
        fpneg751(e);                                           // e = -(b-a)
        fpcorrection751(d);
        fpcorrection751(e);
        if (fpcompare751(d,e)!=0) { passed=0; break; }

        fpzero751(b);
        fpsub751(a, b, d);                                     // d = a-0 
        if (fpcompare751(a,d)!=0) { passed=0; break; }
        
        fpzero751(b);
        fpcopy751(a, d);                 
        fpsub751(a, d, e);                                     // e = a+(-a)
        fpcorrection751(e);
        if (fpcompare751(e,b)!=0) { passed=0; break; }
    }
    if (passed==1) printf("  GF(p) subtraction tests ......................................... PASSED");
    else { printf("  GF(p) subtraction tests... FAILED"); printf("\n"); return false; }
    printf("\n");

    // Field multiplication over the prime p751
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {    
        fprandom751_test(a); fprandom751_test(b); fprandom751_test(c);  
        fprandom751_test(ma); fprandom751_test(mb); fprandom751_test(mc); fprandom751_test(md); fprandom751_test(me); fprandom751_test(mf); 

        to_mont(a, ma);
        fpcopy751(ma, mc);
        from_mont(mc, c);
        if (fpcompare751(a,c)!=0) { passed=0; break; }

        fpmul751_mont_basic(ma, mb, mc);
        fpmul751_mont(ma, mb, md);
        from_mont(mc, c);
        from_mont(md, d);
        if (fpcompare751(c,d)!=0) { passed=0; break; }
        
        to_mont(a, ma); to_mont(b, mb); to_mont(c, mc); 
        fpmul751_mont(ma, mb, md); fpmul751_mont(md, mc, me);                          // e = (a*b)*c
        fpmul751_mont(mb, mc, md); fpmul751_mont(md, ma, mf);                          // f = a*(b*c)
        from_mont(me, e);
        from_mont(mf, f);
        if (fpcompare751(e,f)!=0) { passed=0; break; }
      
        to_mont(a, ma); to_mont(b, mb); to_mont(c, mc); 
        fpadd751(mb, mc, md); fpmul751_mont(ma, md, me);                               // e = a*(b+c)
        fpmul751_mont(ma, mb, md); fpmul751_mont(ma, mc, mf); fpadd751(md, mf, mf);    // f = a*b+a*c
        from_mont(me, e);
        from_mont(mf, f);
        if (fpcompare751(e,f)!=0) { passed=0; break; }
       
        to_mont(a, ma); to_mont(b, mb);
        fpmul751_mont(ma, mb, md);                                                      // d = a*b 
        fpmul751_mont(mb, ma, me);                                                      // e = b*a 
        from_mont(md, d);
        from_mont(me, e);
        if (fpcompare751(d,e)!=0) { passed=0; break; }
        
        to_mont(a, ma);
        fpzero751(b); b[0] = 1; to_mont(b, mb);
        fpmul751_mont(ma, mb, md);                                                      // d = a*1  
        from_mont(ma, a);
        from_mont(md, d);                
        if (fpcompare751(a,d)!=0) { passed=0; break; }
        
        fpzero751(b); to_mont(b, mb);
        fpmul751_mont(ma, mb, md);                                                      // d = a*0  
        from_mont(mb, b);
        from_mont(md, d);                
        if (fpcompare751(b,d)!=0) { passed=0; break; } 
    }
    if (passed==1) printf("  GF(p) multiplication tests ...................................... PASSED");
    else { printf("  GF(p) multiplication tests... FAILED"); printf("\n"); return false; }
    printf("\n");

    // Field squaring over the prime p751
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fprandom751_test(a);
        
        to_mont(a, ma);
        fpsqr751_mont(ma, mb);                                 // b = a^2
        fpmul751_mont(ma, ma, mc);                             // c = a*a 
        if (fpcompare751(mb,mc)!=0) { passed=0; break; }

        fpzero751(a); to_mont(a, ma);
        fpsqr751_mont(ma, md);                                 // d = 0^2 
        if (fpcompare751(ma,md)!=0) { passed=0; break; }
    }
    if (passed==1) printf("  GF(p) squaring tests............................................. PASSED");
    else { printf("  GF(p) squaring tests... FAILED"); printf("\n"); return false; }
    printf("\n");
    
    // Field inversion over the prime p751
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fprandom751_test(a); 
        to_mont(a, ma);
        fpzero751(d); d[0]=1; to_mont(d, md);
        fpcopy751(ma, mb);                            
        fpinv751_mont(ma);                                
        fpmul751_mont(ma, mb, mc);                             // c = a*a^-1 
        if (fpcompare751(mc,md)!=0) { passed=0; break; }
		
		fprandom751_test(a);
		to_mont(a, ma);
		fpcopy751(ma, mb);
		fpinv751_mont(ma);                                     // a = a^-1 by exponentiation
		fpinv751_mont_bingcd(mb);                              // b = a^-1 by binary GCD
		if (fpcompare751(ma, mb) != 0) { passed = 0; break; }
    }
    if (passed==1) printf("  GF(p) inversion tests............................................ PASSED");
    else { printf("  GF(p) inversion tests... FAILED"); printf("\n"); return false; }
    printf("\n");
    
    return OK;
}


bool fp2_test()
{ // Tests for the quadratic extension field arithmetic
    bool OK = true;
    int n, passed;
    f2elm_t a, b, c, d, e, f, ma, mb, mc, md, me, mf;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Testing quadratic extension arithmetic over GF(p751^2): \n\n"); 

    // Addition over GF(p751^2)
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fp2random751_test(a); fp2random751_test(b); fp2random751_test(c); fp2random751_test(d); fp2random751_test(e); fp2random751_test(f); 

        fp2add751(a, b, d); fp2add751(d, c, e);                 // e = (a+b)+c
        fp2add751(b, c, d); fp2add751(d, a, f);                 // f = a+(b+c)
        if (fp2compare751(e,f)!=0) { passed=0; break; }

        fp2add751(a, b, d);                                     // d = a+b 
        fp2add751(b, a, e);                                     // e = b+a
        if (fp2compare751(d,e)!=0) { passed=0; break; }

        fp2zero751(b);
        fp2add751(a, b, d);                                     // d = a+0 
        if (fp2compare751(a,d)!=0) { passed=0; break; }
        
        fp2zero751(b);
        fp2copy751(a, d);     
        fp2neg751(d);                      
        fp2add751(a, d, e);                                     // e = a+(-a)
        if (fp2compare751(e,b)!=0) { passed=0; break; }
    }
    if (passed==1) printf("  GF(p^2) addition tests .......................................... PASSED");
    else { printf("  GF(p^2) addition tests... FAILED"); printf("\n"); return false; }
    printf("\n");

    // Subtraction over GF(p751^2)
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fp2random751_test(a); fp2random751_test(b); fp2random751_test(c); fp2random751_test(d); fp2random751_test(e); fp2random751_test(f); 

        fp2sub751(a, b, d); fp2sub751(d, c, e);                 // e = (a-b)-c
        fp2add751(b, c, d); fp2sub751(a, d, f);                 // f = a-(b+c)
        if (fp2compare751(e,f)!=0) { passed=0; break; }

        fp2sub751(a, b, d);                                     // d = a-b 
        fp2sub751(b, a, e);                                         
        fp2neg751(e);                                           // e = -(b-a)
        if (fp2compare751(d,e)!=0) { passed=0; break; }

        fp2zero751(b);
        fp2sub751(a, b, d);                                     // d = a-0 
        if (fp2compare751(a,d)!=0) { passed=0; break; }
        
        fp2zero751(b);
        fp2copy751(a, d);                 
        fp2sub751(a, d, e);                                     // e = a+(-a)
        if (fp2compare751(e,b)!=0) { passed=0; break; }
    }
    if (passed==1) printf("  GF(p^2) subtraction tests ....................................... PASSED");
    else { printf("  GF(p^2) subtraction tests... FAILED"); printf("\n"); return false; }
    printf("\n");

    // Multiplication over GF(p751^2)
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {    
        fp2random751_test(a); fp2random751_test(b); fp2random751_test(c);  
        fp2random751_test(ma); fp2random751_test(mb); fp2random751_test(mc); fp2random751_test(md); fp2random751_test(me); fp2random751_test(mf); 

        to_fp2mont(a, ma);
        fp2copy751(ma, mc);
        from_fp2mont(mc, c);
        if (fp2compare751(a,c)!=0) { passed=0; break; }
        
        to_fp2mont(a, ma); to_fp2mont(b, mb); to_fp2mont(c, mc); 
        fp2mul751_mont(ma, mb, md); fp2mul751_mont(md, mc, me);                          // e = (a*b)*c
        fp2mul751_mont(mb, mc, md); fp2mul751_mont(md, ma, mf);                          // f = a*(b*c)
        from_fp2mont(me, e);
        from_fp2mont(mf, f);
        if (fp2compare751(e,f)!=0) { passed=0; break; }
      
        to_fp2mont(a, ma); to_fp2mont(b, mb); to_fp2mont(c, mc); 
        fp2add751(mb, mc, md); fp2mul751_mont(ma, md, me);                               // e = a*(b+c)
        fp2mul751_mont(ma, mb, md); fp2mul751_mont(ma, mc, mf); fp2add751(md, mf, mf);   // f = a*b+a*c
        from_fp2mont(me, e);
        from_fp2mont(mf, f);
        if (fp2compare751(e,f)!=0) { passed=0; break; }
       
        to_fp2mont(a, ma); to_fp2mont(b, mb);
        fp2mul751_mont(ma, mb, md);                                                      // d = a*b 
        fp2mul751_mont(mb, ma, me);                                                      // e = b*a 
        from_fp2mont(md, d);
        from_fp2mont(me, e);
        if (fp2compare751(d,e)!=0) { passed=0; break; }
        
        to_fp2mont(a, ma);
        fp2zero751(b); b[0][0] = 1; to_fp2mont(b, mb);
        fp2mul751_mont(ma, mb, md);                                                      // d = a*1  
        from_fp2mont(md, d);               
        if (fp2compare751(a,d)!=0) { passed=0; break; }
        
        fp2zero751(b); to_fp2mont(b, mb);
        fp2mul751_mont(ma, mb, md);                                                      // d = a*0 
        from_fp2mont(md, d);               
        if (fp2compare751(b,d)!=0) { passed=0; break; } 
    }
    if (passed==1) printf("  GF(p^2) multiplication tests .................................... PASSED");
    else { printf("  GF(p^2) multiplication tests... FAILED"); printf("\n"); return false; }
    printf("\n");

    // Squaring over GF(p751^2)
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fp2random751_test(a);
        
        to_fp2mont(a, ma);
        fp2sqr751_mont(ma, mb);                                 // b = a^2
        fp2mul751_mont(ma, ma, mc);                             // c = a*a 
        from_fp2mont(mb, b);               
        from_fp2mont(mc, c);               
        if (fp2compare751(b,c)!=0) { passed=0; break; }

        fp2zero751(a); to_fp2mont(a, ma);
        fp2sqr751_mont(ma, md);                                 // d = 0^2 
        from_fp2mont(md, d);               
        if (fp2compare751(a,d)!=0) { passed=0; break; }
    }
    if (passed==1) printf("  GF(p^2) squaring tests........................................... PASSED");
    else { printf("  GF(p^2) squaring tests... FAILED"); printf("\n"); return false; }
    printf("\n");
    
    // Inversion over GF(p751^2)
    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {
        fp2random751_test(a);    
        
        to_fp2mont(a, ma);
        fp2zero751(d); d[0][0]=1; to_fp2mont(d, md);
        fp2copy751(ma, mb);                            
        fp2inv751_mont(ma);                                
        fp2mul751_mont(ma, mb, mc);                             // c = a*a^-1              
        from_fp2mont(mc, c);  
        if (fp2compare751(c,d)!=0) { passed=0; break; }

		fp2random751_test(a);

		to_fp2mont(a, ma);
		fp2copy751(ma, mb);
		fp2inv751_mont(ma);                                    // a = a^-1 with exponentiation
		fp2inv751_mont_bingcd(mb);                             // a = a^-1 with binary GCD
		if (fp2compare751(ma, mb) != 0) { passed = 0; break; }
    }
    if (passed==1) printf("  GF(p^2) inversion tests.......................................... PASSED");
    else { printf("  GF(p^2) inversion tests... FAILED"); printf("\n"); return false; }
    printf("\n");
    
    return OK;
}


bool fp_run()
{
    bool OK = true;
    int n;
    unsigned long long cycles, cycles1, cycles2;
    felm_t a, b, c;
    dfelm_t aa;
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Benchmarking field arithmetic over GF(p751): \n\n"); 
        
    fprandom751_test(a); fprandom751_test(b); fprandom751_test(c);

    // GF(p) addition using p751
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fpadd751(a, b, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p) addition runs in .......................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p) subtraction using p751
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fpsub751(a, b, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p) subtraction runs in ....................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p) multiplication using p751
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fpmul751_mont(a, b, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p) multiplication runs in .................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p) reduction using p751
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        mp_mul(a, b, aa, NWORDS_FIELD);

        cycles1 = cpucycles(); 
        rdc_mont(aa, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p) reduction runs in ......................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p) inversion
    cycles = 0;
    for (n=0; n<SMALL_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fpinv751_mont(a);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p) inversion (exponentiation) runs in ........................ %7lld ", cycles/SMALL_BENCH_LOOPS); print_unit;
    printf("\n");

	// GF(p) inversion, binary GCD
	cycles = 0;
	for (n = 0; n<SMALL_BENCH_LOOPS; n++)
	{
		cycles1 = cpucycles();
		fpinv751_mont_bingcd(a);
		cycles2 = cpucycles();
		cycles = cycles + (cycles2 - cycles1);
	}
	printf("  GF(p) inversion (binary GCD) runs in ............................ %7lld ", cycles/SMALL_BENCH_LOOPS); print_unit;
	printf("\n");
    
    return OK;
}


bool fp2_run()
{
    bool OK = true;
    int n;
    unsigned long long cycles, cycles1, cycles2;
    f2elm_t a, b, c;
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Benchmarking quadratic extension arithmetic over GF(p751^2): \n\n"); 
    
    fp2random751_test(a); fp2random751_test(b); fp2random751_test(c);

    // GF(p^2) addition
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fp2add751(a, b, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p^2) addition runs in ........................................ %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p^2) subtraction
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fp2sub751(a, b, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p^2) subtraction runs in ..................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p^2) multiplication
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fp2mul751_mont(a, b, c);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p^2) multiplication runs in .................................. %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p^2) squaring
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fp2sqr751_mont(a, b);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p^2) squaring runs in ........................................ %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // GF(p^2) inversion
    cycles = 0;
    for (n=0; n<SMALL_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        fp2inv751_mont(a);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  GF(p^2) inversion (exponentiation) runs in ...................... %7lld ", cycles/SMALL_BENCH_LOOPS); print_unit;
    printf("\n");

	// GF(p^2) inversion with binary GCD (NOT constant time!!!)
	cycles = 0;
	for (n = 0; n<SMALL_BENCH_LOOPS; n++)
	{
		cycles1 = cpucycles();
		fp2inv751_mont_bingcd(a);
		cycles2 = cpucycles();
		cycles = cycles + (cycles2 - cycles1);
	}
	printf("  GF(p^2) inversion (binary GCD) runs in .......................... %7lld ", cycles/SMALL_BENCH_LOOPS); print_unit;
	printf("\n");
    
    return OK;
}


bool ecisog_run(PCurveIsogenyStaticData CurveIsogenyData)
{
    bool OK = true;
    int n;
    unsigned long long cycles, cycles1, cycles2;
    f2elm_t A24, C24, A4, A, C, Aout, Cout, coeff[5];
    point_proj_t P, Q;
    PCurveIsogenyStruct CurveIsogeny = {0};
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        OK = false;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        OK = false;
        goto cleanup;
    }
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Benchmarking elliptic curve and isogeny functions: \n\n"); 

    // Point doubling
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        fp2random751_test(A24); fp2random751_test(C24);

        cycles1 = cpucycles(); 
        xDBL(P, Q, A24, C24);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Point doubling runs in .......................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // 4-isogeny of a projective point
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        fp2random751_test(A); fp2random751_test(coeff[0]); fp2random751_test(coeff[1]); fp2random751_test(coeff[2]); fp2random751_test(coeff[3]); fp2random751_test(coeff[4]);

        cycles1 = cpucycles(); 
        get_4_isog(P, A, C, coeff);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  4-isogeny of projective point runs in ........................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // 4-isogeny evaluation at projective point
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        fp2random751_test(A); fp2random751_test(coeff[0]); fp2random751_test(coeff[1]); fp2random751_test(coeff[2]); fp2random751_test(coeff[3]); fp2random751_test(coeff[4]);

        cycles1 = cpucycles(); 
        eval_4_isog(P, coeff);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  4-isogeny evaluation at projective point runs in ................ %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // First 4-isogeny of projective point
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        fp2random751_test(A); fp2random751_test(coeff[0]); fp2random751_test(coeff[1]); fp2random751_test(coeff[2]); fp2random751_test(coeff[3]); fp2random751_test(coeff[4]);

        cycles1 = cpucycles(); 
        first_4_isog(P, A, Aout, Cout, CurveIsogeny);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  First 4-isogeny of projective point runs in ..................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // Point tripling
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        fp2random751_test(A4); fp2random751_test(C);

        cycles1 = cpucycles(); 
        xTPL(P, Q, A4, C);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Point tripling runs in .......................................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // 3-isogeny of a projective point
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        fp2random751_test(A); fp2random751_test(C);

        cycles1 = cpucycles(); 
        get_3_isog(P, A, C);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  3-isogeny of projective point runs in ........................... %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // 3-isogeny evaluation at projective point
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        eval_3_isog(P, Q);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  3-isogeny evaluation at projective point runs in ................ %7lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

cleanup:
    SIDH_curve_free(CurveIsogeny);
    
    return OK;
}


bool ecpoints_test(PCurveIsogenyStaticData CurveIsogenyData)
{
	bool OK = true;
	unsigned int i;
	unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
	unsigned int obytes = (CurveIsogenyData->owordbits + 7)/8;      // Number of bytes in an element in [1, order]
	unsigned char *PrivateKeyA, *PublicKeyA, *PrivateKeyB, *PublicKeyB;
	f2elm_t t0, t1;
	f2elm_t A, C, zero, one, PK0, PK1, PK2;
	point_full_proj_t R1, R2;
	point_proj_t P1, P2, P3, P4;
	PCurveIsogenyStruct CurveIsogeny = {0};
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	bool passed;

	// Allocating memory for private keys, public keys and shared secrets
	// Do this to obtain "random" curves.
	PrivateKeyA = (unsigned char*)calloc(1, obytes);            // One element in [1, order]  
	PrivateKeyB = (unsigned char*)calloc(1, obytes);
	PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);         // Three elements in GF(p^2)
	PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);

	printf("\n--------------------------------------------------------------------------------------------------------\n\n");
	printf("Testing elliptic curve point generation functions: \n\n");

	// Curve isogeny system initialization
	CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		OK = false;
		goto cleanup;
	}
	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
	if (Status != CRYPTO_SUCCESS) {
		OK = false;
		goto cleanup;
	}

	fp2zero751(zero);
	fp2zero751(one);
	fp2zero751(C);
	fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
	fpcopy751(one[0], C[0]);

	// Generating a 2-torsion basis
	passed = 1;
	for (i = 0; i < ECPT_TEST_LOOPS; i++)
	{
		Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);      // Get some value as Alice's secret key and compute Alice's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}
		to_fp2mont(((f2elm_t*)PublicKeyA)[0], PK0);
		to_fp2mont(((f2elm_t*)PublicKeyA)[1], PK1);
		to_fp2mont(((f2elm_t*)PublicKeyA)[2], PK2);
		get_A(PK0, PK1, PK2, A, CurveIsogeny);

		generate_2_torsion_basis(A, R1, R2, CurveIsogeny);

		fp2copy751(R1->X, P1->X);
		fp2copy751(R1->Z, P1->Z);
		fp2copy751(R2->X, P2->X);
		fp2copy751(R2->Z, P2->Z);

		// Check order of R1 
		xDBLe(P1, P3, A, C, 371);
		xDBLe(P3, P1, A, C, 1);
		fp2correction751(P1->Z);
		if (fp2compare751(P1->Z, zero) != 0) { printf("R1\n"); passed = 0; break; }
		// Check order of R2 
		xDBLe(P2, P4, A, C, 371);
		xDBLe(P4, P2, A, C, 1);
		fp2correction751(P2->Z);
		if (fp2compare751(P2->Z, zero) != 0) { printf("R2\n"); passed = 0; break; }
		// Check that the order of WeilPairing(R1,R2) is oA
		fp2mul751_mont(P3->Z, P4->X, t0);
		fp2mul751_mont(P3->X, P4->Z, t1);
		fp2sub751(t0, t1, t0);
		fp2correction751(t0);
		if (fp2compare751(t0, zero) == 0) { printf("e(R1,R2)\n"); passed = 0; break; }

	}
	if (passed == 1) printf("  Computing 2-torsion basis tests........................................ PASSED");
	else { printf("  Computing 2-torsion basis tests... FAILED"); printf("\n"); return false; }
	printf("\n");

	// Generating a 3-torsion basis
	passed = 1;
	for (i = 0; i < ECPT_TEST_LOOPS; i++)
	{
		//printf("%d ",i);
		Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);      // Get some value as Alice's secret key and compute Alice's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}
		to_fp2mont(((f2elm_t*)PublicKeyB)[0], PK0);
		to_fp2mont(((f2elm_t*)PublicKeyB)[1], PK1);
		to_fp2mont(((f2elm_t*)PublicKeyB)[2], PK2);
		get_A(PK0, PK1, PK2, A, CurveIsogeny);

		generate_3_torsion_basis(A, R1, R2, CurveIsogeny);

		fp2copy751(R1->X, P1->X);
		fp2copy751(R1->Z, P1->Z);
		fp2copy751(R2->X, P2->X);
		fp2copy751(R2->Z, P2->Z);

		// Check order of R1 by xTPL(R1, P1, A, 1); and check that P1->Z is zero
		xTPLe(P1, P3, A, C, 238);
		xTPLe(P3, P1, A, C, 1);
		fp2correction751(P1->Z);
		if (fp2compare751(P1->Z, zero) != 0) { printf("R1\n"); passed = 0; break; }
		// Check order of R2 by xTPL(R2, P2, A, 1); and check that P2->Z is zero
		xTPLe(P2, P4, A, C, 238);
		xTPLe(P4, P2, A, C, 1);
		fp2correction751(P2->Z);
		if (fp2compare751(P2->Z, zero) != 0) { printf("R2\n"); passed = 0; break; }
		// Check that the order of WeilPairing(R1,R2) is oB
		fp2mul751_mont(P3->Z, P4->X, t0);
		fp2mul751_mont(P3->X, P4->Z, t1);
		fp2sub751(t0, t1, t0);
		fp2correction751(t0);
		if (fp2compare751(t0, zero) == 0) { printf("e(R1,R2)\n"); passed = 0; break; }
	}
	if (passed == 1) printf("  Computing 3-torsion basis tests........................................ PASSED");
	else { printf("  Computing 3-torsion basis tests... FAILED"); printf("\n"); return false; }
	printf("\n");

cleanup:
	SIDH_curve_free(CurveIsogeny);    
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);

	return OK;
}


bool ecpairing_test(PCurveIsogenyStaticData CurveIsogenyData)
{
		bool OK = true;
		unsigned int i, j;
		unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
		unsigned int obytes = (CurveIsogenyData->owordbits + 7)/8;      // Number of bytes in an element in [1, order]
		unsigned char *PrivateKeyA, *PublicKeyA, *PrivateKeyB, *PublicKeyB;
		f2elm_t t0, t1;
		f2elm_t A, C, A24, C24, zero, one, PK0, PK1, PK2, pairings[5];
		point_full_proj_t R1, R2, Q1, Q2, Q3, Q4;
		point_proj_t P1, P2, P3, P4, P5;
		point_t S1, S2, SP, SQ;
		PCurveIsogenyStruct CurveIsogeny = {0};
		CRYPTO_STATUS Status = CRYPTO_SUCCESS;
		digit_t m1[NWORDS_ORDER], m2[NWORDS_ORDER], n1[NWORDS_ORDER], n2[NWORDS_ORDER];
		digit_t mm1[NWORDS_ORDER], mm2[NWORDS_ORDER], nn1[NWORDS_ORDER], nn2[NWORDS_ORDER];
		bool passed;

		// Allocating memory for private keys, public keys and shared secrets
		// Do this to obtain "random" curves.
		PrivateKeyA = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
		PrivateKeyB = (unsigned char*)calloc(1, obytes);
		PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);     // Three elements in GF(p^2)
		PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);

		printf("\n--------------------------------------------------------------------------------------------------------\n\n");
		printf("Testing pairing functions: \n\n");

		// Curve isogeny system initialization
		CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
		if (CurveIsogeny == NULL) {
			OK = false;
			Status = CRYPTO_ERROR_NO_MEMORY;
			goto cleanup;
		}
		Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}

		fp2zero751(zero);
		fp2zero751(one);
		fp2zero751(C);
		fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
		fpcopy751(one[0], C[0]);

	// Testing 2-torsion pairings
	passed = 1;
	for (i = 0; i < ECPAIR_TEST_LOOPS; i++)
	{
		Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);      // Get some value as Alice's secret key and compute Alice's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}
		to_fp2mont(((f2elm_t*)PublicKeyA)[0], PK0);
		to_fp2mont(((f2elm_t*)PublicKeyA)[1], PK1);
		to_fp2mont(((f2elm_t*)PublicKeyA)[2], PK2);
		get_A(PK0, PK1, PK2, A, CurveIsogeny);
		fp2correction751(A);

		generate_2_torsion_basis(A, R1, R2, CurveIsogeny);

		fp2copy751(R1->Z, S1->x);
		fp2copy751(R2->Z, S2->x);
		fp2inv751_mont_bingcd(S1->x);
		fp2inv751_mont_bingcd(S2->x);
		fp2mul751_mont(S1->x, R1->Y, S1->y);
		fp2mul751_mont(S1->x, R1->X, S1->x);
		fp2mul751_mont(S2->x, R2->Y, S2->y);
		fp2mul751_mont(S2->x, R2->X, S2->x);

		// Choose random scalars modulo Alice's group order (2^372).
		Status = random_mod_order(m1, ALICE, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m1, NWORDS_ORDER);
			return Status;
		}
		Status = random_mod_order(n1, ALICE, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m1, NWORDS_ORDER);
			return Status;
		}
		Status = random_mod_order(m2, ALICE, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m2, NWORDS_ORDER);
			return Status;
		}
		Status = random_mod_order(n2, ALICE, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m2, NWORDS_ORDER);
			return Status;
		}

		// Store for checking the powers of the pairings later.
		copy_words(m1, mm1, NWORDS_ORDER);
		copy_words(n1, nn1, NWORDS_ORDER);
		copy_words(m2, mm2, NWORDS_ORDER);
		copy_words(n2, nn2, NWORDS_ORDER);

		fpzero751(C24[1]);
		fpadd751(one[0], one[0], C24[0]);
		fp2add751(C24, A, A24);
		fpadd751(C24[0], C24[0], C24[0]);
		fp2inv751_mont_bingcd(C24);
		fp2mul751_mont(A24, C24, A24);

		// Compute scalar multiples with the Montgomery ladder.
		Mont_ladder(S1->x, m1, P1, P5, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
		Mont_ladder(S2->x, n1, P2, P5, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
		Mont_ladder(S1->x, m2, P3, P5, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
		Mont_ladder(S2->x, n2, P4, P5, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);

		// Recover y-coordinates, unique only up to sign.
		fp2copy751(P1->X, Q1->X);
		fp2copy751(P1->Z, Q1->Z);
		fp2inv751_mont_bingcd(Q1->Z);
		fp2mul751_mont(Q1->X, Q1->Z, Q1->X);
		fp2correction751(Q1->X);
		fp2copy751(one, Q1->Z);
		fp2mul751_mont(Q1->X, Q1->X, t0);
		fp2mul751_mont(A, Q1->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q1->X, t0, t0);
		fp2add751(Q1->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q1->Y);
		fp2correction751(Q1->Y);

		fp2copy751(P2->X, Q2->X);
		fp2copy751(P2->Z, Q2->Z);
		fp2inv751_mont_bingcd(Q2->Z);
		fp2mul751_mont(Q2->X, Q2->Z, Q2->X);
		fp2correction751(Q2->X);
		fp2copy751(one, Q2->Z);
		fp2mul751_mont(Q2->X, Q2->X, t0);
		fp2mul751_mont(A, Q2->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q2->X, t0, t0);
		fp2add751(Q2->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q2->Y);
		fp2correction751(Q2->Y);
		
		fp2copy751(P3->X, Q3->X);
		fp2copy751(P3->Z, Q3->Z);
		fp2inv751_mont_bingcd(Q3->Z);
		fp2mul751_mont(Q3->X, Q3->Z, Q3->X);
		fp2correction751(Q3->X);
		fp2copy751(one, Q3->Z);
		fp2mul751_mont(Q3->X, Q3->X, t0);
		fp2mul751_mont(A, Q3->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q3->X, t0, t0);
		fp2add751(Q3->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q3->Y);
		fp2correction751(Q3->Y);

		fp2copy751(P4->X, Q4->X);
		fp2copy751(P4->Z, Q4->Z);
		fp2inv751_mont_bingcd(Q4->Z);
		fp2mul751_mont(Q4->X, Q4->Z, Q4->X);
		fp2correction751(Q4->X);
		fp2copy751(one, Q4->Z);
		fp2mul751_mont(Q4->X, Q4->X, t0);
		fp2mul751_mont(A, Q4->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q4->X, t0, t0);
		fp2add751(Q4->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q4->Y);
		fp2correction751(Q4->Y);

		// Compute P = (+-)m1*R1 (+-) n1*R2 and Q = (+-)m2*R1 (+-) n2*R2.
		// Signs depend on which y-coordinates were recovered.
		ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q1);
		ADD(Q3, Q4->X, Q4->Y, Q4->Z, A, Q3);

		// Normalize to affine coordinates.
		fp2copy751(Q1->Z, SP->x);
		fp2copy751(Q3->Z, SQ->x);
		fp2inv751_mont_bingcd(SP->x);
		fp2inv751_mont_bingcd(SQ->x);
		fp2mul751_mont(SP->x, Q1->Y, SP->y);
		fp2mul751_mont(SP->x, Q1->X, SP->x);
		fp2mul751_mont(SQ->x, Q3->Y, SQ->y);
		fp2mul751_mont(SQ->x, Q3->X, SQ->x);
		fp2correction751(SP->x);
		fp2correction751(SP->y);
		fp2correction751(SQ->x);
		fp2correction751(SQ->y);

		// Compute the 2-torsion pairings.
		Tate_pairings_2_torsion(S1, S2, SP, SQ, A, pairings, CurveIsogeny);

		// Check for bilinearity up to sign of the scalars.
		exp_Fp2_cycl(pairings[0], (uint64_t*)nn1, one[0], t0, 372);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[1][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[1][1]) != 0) { 
		    inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[1][1]) != 0) { passed = 0; break; }
		}
		exp_Fp2_cycl(pairings[0], (uint64_t*)nn2, one[0], t0, 372);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[2][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[2][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[2][1]) != 0) { passed = 0; break; }
		}
		exp_Fp2_cycl(pairings[0], (uint64_t*)mm1, one[0], t0, 372);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[3][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[3][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[3][1]) != 0) { passed = 0; break; }
		}
		exp_Fp2_cycl(pairings[0], (uint64_t*)mm2, one[0], t0, 372);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[4][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[4][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[4][1]) != 0) { passed = 0; break; }
		}
	}
	if (passed == 1) printf("  2-torsion pairing tests................................................ PASSED");
	else { printf("  2-torsion pairing tests... FAILED"); printf("\n"); return false; }
	printf("\n");

	// Testing 3-torsion pairings
	passed = 1;
	for (i = 0; i < ECPAIR_TEST_LOOPS; i++)
	{
		Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);      // Get some value as Alice's secret key and compute Alice's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}
		to_fp2mont(((f2elm_t*)PublicKeyB)[0], PK0);
		to_fp2mont(((f2elm_t*)PublicKeyB)[1], PK1);
		to_fp2mont(((f2elm_t*)PublicKeyB)[2], PK2);
		get_A(PK0, PK1, PK2, A, CurveIsogeny);
		fp2correction751(A);

		generate_3_torsion_basis(A, R1, R2, CurveIsogeny);

		fp2copy751(R1->Z, S1->x);
		fp2copy751(R2->Z, S2->x);
		fp2inv751_mont_bingcd(S1->x);
		fp2inv751_mont_bingcd(S2->x);
		fp2mul751_mont(S1->x, R1->Y, S1->y);
		fp2mul751_mont(S1->x, R1->X, S1->x);
		fp2mul751_mont(S2->x, R2->Y, S2->y);
		fp2mul751_mont(S2->x, R2->X, S2->x);
		fp2correction751(S1->x);
		fp2correction751(S1->y);
		fp2correction751(S2->x);
		fp2correction751(S2->y);

		// Choose random scalars modulo Bob's group order (3^239).
		Status = random_mod_order(m1, BOB, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m1, NWORDS_ORDER);
			return Status;
		}
		Status = random_mod_order(n1, BOB, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m1, NWORDS_ORDER);
			return Status;
		}
		Status = random_mod_order(m2, BOB, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m2, NWORDS_ORDER);
			return Status;
		}
		Status = random_mod_order(n2, BOB, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			clear_words(m2, NWORDS_ORDER);
			return Status;
		}

		// Store for checking the powers of the pairings later.
		copy_words(m1, mm1, NWORDS_ORDER);
		copy_words(n1, nn1, NWORDS_ORDER);
		copy_words(m2, mm2, NWORDS_ORDER);
		copy_words(n2, nn2, NWORDS_ORDER);

		fpzero751(C24[1]);
		fpadd751(one[0], one[0], C24[0]);
		fp2add751(C24, A, A24);
		fpadd751(C24[0], C24[0], C24[0]);
		fp2inv751_mont_bingcd(C24);
		fp2mul751_mont(A24, C24, A24);

		// Compute scalar multiples with the Montgomery ladder.
		Mont_ladder(S1->x, m1, P1, P5, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
		Mont_ladder(S2->x, n1, P2, P5, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
		Mont_ladder(S1->x, m2, P3, P5, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
		Mont_ladder(S2->x, n2, P4, P5, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);

		// Recover y-coordinates, unique only up to sign.
		fp2copy751(P1->X, Q1->X);
		fp2copy751(P1->Z, Q1->Z);
		fp2inv751_mont_bingcd(Q1->Z);
		fp2mul751_mont(Q1->X, Q1->Z, Q1->X);
		fp2correction751(Q1->X);
		fp2copy751(one, Q1->Z);
		fp2mul751_mont(Q1->X, Q1->X, t0);
		fp2mul751_mont(A, Q1->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q1->X, t0, t0);
		fp2add751(Q1->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q1->Y);
		fp2correction751(Q1->Y);

		fp2copy751(P2->X, Q2->X);
		fp2copy751(P2->Z, Q2->Z);
		fp2inv751_mont_bingcd(Q2->Z);
		fp2mul751_mont(Q2->X, Q2->Z, Q2->X);
		fp2correction751(Q2->X);
		fp2copy751(one, Q2->Z);
		fp2mul751_mont(Q2->X, Q2->X, t0);
		fp2mul751_mont(A, Q2->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q2->X, t0, t0);
		fp2add751(Q2->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q2->Y);
		fp2correction751(Q2->Y);

		fp2copy751(P3->X, Q3->X);
		fp2copy751(P3->Z, Q3->Z);
		fp2inv751_mont_bingcd(Q3->Z);
		fp2mul751_mont(Q3->X, Q3->Z, Q3->X);
		fp2correction751(Q3->X);
		fp2copy751(one, Q3->Z);
		fp2mul751_mont(Q3->X, Q3->X, t0);
		fp2mul751_mont(A, Q3->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q3->X, t0, t0);
		fp2add751(Q3->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q3->Y);
		fp2correction751(Q3->Y);

		fp2copy751(P4->X, Q4->X);
		fp2copy751(P4->Z, Q4->Z);
		fp2inv751_mont_bingcd(Q4->Z);
		fp2mul751_mont(Q4->X, Q4->Z, Q4->X);
		fp2correction751(Q4->X);
		fp2copy751(one, Q4->Z);
		fp2mul751_mont(Q4->X, Q4->X, t0);
		fp2mul751_mont(A, Q4->X, t1);
		fp2add751(t0, t1, t0);
		fp2mul751_mont(Q4->X, t0, t0);
		fp2add751(Q4->X, t0, t0);                     // t0 = X^3+A*X^2+X;
		fp2correction751(t0);
		sqrt_Fp2(t0, Q4->Y);
		fp2correction751(Q4->Y);

		// Compute P = (+-)m1*R1 (+-) n1*R2 and Q = (+-)m2*R1 (+-) n2*R2.
		// Signs depend on which y-coordinates were recovered.
		ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q1);
		ADD(Q3, Q4->X, Q4->Y, Q4->Z, A, Q3);

		// Normalize to affine coordinates.
		fp2copy751(Q1->Z, SP->x);
		fp2copy751(Q3->Z, SQ->x);
		fp2inv751_mont_bingcd(SP->x);
		fp2inv751_mont_bingcd(SQ->x);
		fp2mul751_mont(SP->x, Q1->Y, SP->y);
		fp2mul751_mont(SP->x, Q1->X, SP->x);
		fp2mul751_mont(SQ->x, Q3->Y, SQ->y);
		fp2mul751_mont(SQ->x, Q3->X, SQ->x);
		fp2correction751(SP->x);
		fp2correction751(SP->y);
		fp2correction751(SQ->x);
		fp2correction751(SQ->y);

		// Compute the 3-torsion pairings.
		Tate_pairings_3_torsion(S1, S2, SP, SQ, A, pairings, CurveIsogeny);

        for(j=0; j<5; j++){fp2correction751(pairings[j]);}

		// Check for bilinearity up to sign of the scalars.
		exp_Fp2_cycl(pairings[0], (uint64_t*)nn1, one[0], t0, 379);
		fp2correction751(t0);
        if (fpcompare751(t0[0], pairings[1][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[1][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[1][1]) != 0) { passed = 0; break; }
		}
		exp_Fp2_cycl(pairings[0], (uint64_t*)nn2, one[0], t0, 379);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[2][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[2][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[2][1]) != 0) { passed = 0; break; }
		}
		exp_Fp2_cycl(pairings[0], (uint64_t*)mm1, one[0], t0, 379);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[3][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[3][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[3][1]) != 0) { passed = 0; break; }
		}
		exp_Fp2_cycl(pairings[0], (uint64_t*)mm2, one[0], t0, 379);
		fp2correction751(t0);
		if (fpcompare751(t0[0], pairings[4][0]) != 0) { passed = 0; break; }
		if (fpcompare751(t0[1], pairings[4][1]) != 0) {
			inv_Fp2_cycl(t0);
			fp2correction751(t0);
			if (fpcompare751(t0[1], pairings[4][1]) != 0) { passed = 0; break; }
		}
	}
	if (passed == 1) printf("  3-torsion pairing tests................................................ PASSED");
	else { printf("  3-torsion pairing tests... FAILED"); printf("\n"); return false; }
	printf("\n");

cleanup:
	SIDH_curve_free(CurveIsogeny);    
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);

	return OK;
}


bool ecph_test(PCurveIsogenyStaticData CurveIsogenyData)
{
	bool OK = true;
	unsigned int i, j;
	unsigned int pbytes = (CurveIsogenyData->pwordbits+7)/8;   // Number of bytes in a field element 
	unsigned int obytes = (CurveIsogenyData->owordbits+7)/8;   // Number of bytes in an element in [1, order]
	unsigned char *PrivateKeyA, *PublicKeyA, *PrivateKeyB, *PublicKeyB;
	f2elm_t f, g, h, u;
	f2elm_t one;
	f2elm_t t_ori[5], LUT[5], LUT_0[4], LUT_1[4], LUT_3[6];
	f2elm_t t_ori3[5], LUT3[4], LUT3_0[4], LUT3_1[5];
	PCurveIsogenyStruct CurveIsogeny = {0};
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	uint64_t m21[2], m0[NWORDS64_ORDER];
	uint64_t n21[2], n0[NWORDS64_ORDER];
	uint64_t m1, n1, m5, n5;
	bool passed;
	bool equ = 1;

	// Allocating memory for private keys, public keys and shared secrets
	// Do this to obtain "random" curves.
	PrivateKeyA = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
	PrivateKeyB = (unsigned char*)calloc(1, obytes);
	PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);     // Four elements in GF(p^2)
	PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);

	printf("\n--------------------------------------------------------------------------------------------------------\n\n");
	printf("Testing Pohlig-Hellman functions: \n\n");

	// Curve isogeny system initialization
	CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
	if (CurveIsogeny == NULL) {
		OK = false;
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}
	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
	if (Status != CRYPTO_SUCCESS) {
		OK = false;
		goto cleanup;
	}

	fp2zero751(one);
	fpcopy751(CurveIsogeny->Montgomery_one, one[0]);

	// Element of order 2^372 in Fp2* (in Montgomery representation):
	static uint64_t g0[NWORDS64_FIELD] = { 0x6DC1FB9744174A3B, 0x6FD2179F99D7C37B, 0x25369C448517FC40, 0xD8C81BAF4D65E1E6, 0x60AB3A6DA83F09E4, 0x754136F6128E14D7,
										   0x35D613FB2FF4E209, 0x6806FCE2C60C4D15, 0x3327268789685473, 0xB1E3A35301572E7A, 0x247A710DAAFD3AF2, 0x000001D1269427DF };
	static uint64_t g1[NWORDS64_FIELD] = { 0x0DF04275F2736D0F, 0x7AF3CB47093A6945, 0x2BF9DE10B80D4916, 0xF38473A6EBBD1190, 0x0AFA711413EEFF3A, 0x8B5ED7CB12A34D48,
										   0x8A7744179FCABFB7, 0x767076DCEEBC6F42, 0xDD5257DEFED2BAD0, 0x29F9AAFDBEEA8CA6, 0x34E0880EE6DFE13B, 0x000032A0AFD7E55A };
	fpcopy751((digit_t*)g0, g[0]);
	fpcopy751((digit_t*)g1, g[1]);

	// Element of order 3^239 in Fp2* (in Montgomery representation):
	static uint64_t f0[NWORDS64_FIELD] = { 0x236D32885248C251, 0xEE9FA7DE6BDF0A1A, 0x567F9615D3F7ED21, 0x8CAF3AEC939225BF, 0xCB62DF92F23880E9, 0x146022FAB57C79D3,
										   0xEDAF5A48061F1786, 0x6234FB60033C0CA4, 0x43DA2B8D5139D295, 0x7297169BE2536FC1, 0xC7492AA82868F7F5, 0x00002672C6DBF252 };
	static uint64_t f1[NWORDS64_FIELD] = { 0x072B8A1712B721F3, 0xAF25A23BA40155B3, 0x2249670B18510FBC, 0x481828E3334AB900, 0x295952F8CFED5755, 0x2A175E1E7089F203,
		                                   0x26EF86CF533A402F, 0xF7416274E96F7A16, 0x858485BF1583B705, 0x80BD1C95101D12A7, 0xFF91E7A65D9DF44F, 0x00005B54A9C7FBB9 };

	fpcopy751((digit_t*)f0, f[0]);
	fpcopy751((digit_t*)f1, f[1]);

	// Build the look-up tables from these two elements.
	build_LUTs(g, t_ori, LUT, LUT_0, LUT_1, LUT_3, one[0]);
	build_LUTs_3(f, t_ori3, LUT3, LUT3_0, LUT3_1, one[0]);

	// Testing Pohlig-Hellman DLP algorithms for the 2-torsion group
	passed = 1;
	for (i = 0; i < ECPH_TEST_LOOPS; i++)
	{
		Status = random_mod_order((digit_t*)m0, ALICE, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			clear_words(m0, NWORDS_ORDER);
			return false;
		}

		fp2copy751(g, h);
		
		// Test phn84, Pohlig-Hellman in a group of order 2^372.
		exp_Fp2_cycl(h, m0, one[0], u, 372);
		phn84(u, t_ori, LUT, LUT_0, LUT_1, LUT_3, one[0], n0);
		for (j = 0; j < NWORDS64_ORDER; j++) {
			equ = equ && (n0[j] == m0[j]);
		}
		if (equ == 0) { passed = 0; break; }
		
		// Test phn21, Pohlig-Hellman in a group of order 2^84.
		for (j = 0; j < 288; j++) sqr_Fp2_cycl(h, one[0]);
		m21[0] = m0[0];
		m21[1] = m0[1];
		m21[1] = (m21[1] >> 44);
		exp_Fp2_cycl(h, m21, one[0], u, 84);
		phn21(u, LUT, LUT_0, LUT_1, one[0], n21);
		if ((n21[0] != m21[0]) || (n21[1] != m21[1])) { passed = 0; break; }
        
		// Test phn5, Pohlig-Hellman in a group of order 2^21.
		for (j = 0; j < 63; j++) sqr_Fp2_cycl(h, one[0]);
		m5 = m0[0];
		m5 = (m5 >> 43);
		exp_Fp2_cycl(h, &m5, one[0], u, 21);
		phn5(u, LUT, LUT_1, one[0], &n5);
		if (n5 != m5) { passed = 0; break; }
		
		// Test phn1, Pohlig-Hellman in a group of order 2^5.
		for (j = 0; j < 16; j++) sqr_Fp2_cycl(h, one[0]);
		m1 = m0[0];
		m1 = (m1 >> 59);
		exp_Fp2_cycl(h, &m1, one[0], u, 5);
		phn1(u, LUT, 5, one[0], &n1);
		if (n1 != m1) { passed = 0; break; }
	}
	if (passed == 1) printf("  2-torsion Pohlig-Hellman tests......................................... PASSED");
	else { printf("  2-torsion Pohlig-Hellman tests... FAILED"); printf("\n"); return false; }
	printf("\n");

	// Testing Pohlig-Hellman DLP algorithms for the 3-torsion group
	passed = 1;
	for (i = 0; i < ECPH_TEST_LOOPS; i++)
	{
		Status = random_mod_order((digit_t*)m0, BOB, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			clear_words(m0, NWORDS_ORDER);
			return false;
		}

		fp2copy751(f, h);

		// Test phn61, Pohlig-Hellman in a group of order 3^239.
		exp_Fp2_cycl(h, m0, one[0], u, 379);
		phn61(u, t_ori3, LUT3, LUT3_0, LUT3_1, one[0], n0);
		for (j = 0; j < NWORDS64_ORDER; j++) {
			equ = equ && (n0[j] == m0[j]);
		}
		if (equ == 0) { passed = 0; break; }

		// Test phn15, Pohlig-Hellman in a group of order 3^61.
		for (j = 0; j < 178; j++) cube_Fp2_cycl(h, one[0]);
		m21[0] = m0[0];
		m21[1] = m0[1] % 0x000000019AEB6ECC; //Reducing mod upper part of 3^61 to ensure scalar is smaller than that.
		exp_Fp2_cycl(h, m21, one[0], u, 97);
		phn15(u, LUT3, LUT3_0, LUT3_1, one[0], n21);
		if ((n21[0] != m21[0]) || (n21[1] != m21[1])) { passed = 0; break; }

		// Test phn15_1, Pohlig-Hellman in a group of order 3^56.
		for (j = 0; j < 5; j++) cube_Fp2_cycl(h, one[0]);
		m21[0] = m0[0];
		m21[1] = m0[1] % 0x0000000001B0E72C;//Reducing mod upper part of 3^56 to ensure scalar is smaller than that.
		exp_Fp2_cycl(h, m21, one[0], u, 89);
		phn15_1(u, LUT3, LUT3_0, LUT3_1, one[0], n21);
		if ((n21[0] != m21[0]) || (n21[1] != m21[1])) { passed = 0; break; }

		// Test phn3, Pohlig-Hellman in a group of order 3^15.
		for (j = 0; j < 41; j++) cube_Fp2_cycl(h, one[0]);
		m1 = m0[0];
		m1 = m1 % (uint64_t)0xDAF26B;
		exp_Fp2_cycl(h, &m1, one[0], u, 24);
		phn3(u, LUT3, LUT3_1, one[0], &n1);
		if (n1 != m1) { passed = 0; break; }

		// Test phn1_3, Pohlig-Hellman in a group of order 3^3.
		for (j = 0; j < 12; j++) cube_Fp2_cycl(h, one[0]);
		m1 = m0[0];
		m1 = m1 % 27;
		exp_Fp2_cycl(h, &m1, one[0], u, 5);
		phn1_3(u, LUT3, 3, one[0], &n1);
		if (n1 != m1) { passed = 0; break; }
	
	}
	if (passed == 1) printf("  3-torsion Pohlig-Hellman tests......................................... PASSED");
	else { printf("  3-torsion Pohlig-Hellman tests... FAILED"); printf("\n"); printf("%i", i); return false; }
	printf("\n");


cleanup:
	SIDH_curve_free(CurveIsogeny);    
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);

	return OK;
}


bool eccompress_test(PCurveIsogenyStaticData CurveIsogenyData)
{ // Compression tests
	bool OK = true;
	unsigned int i;
	unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;    // Number of bytes in a field element 
	unsigned int obytes = (CurveIsogenyData->owordbits + 7)/8;    // Number of bytes in an element in [1, order]
	unsigned char temp, bit, *PrivateKeyA, *PublicKeyA, *PrivateKeyB, *PublicKeyB, *CompressedPKA, *CompressedPKB, *SharedSecret1, *SharedSecret2;
	f2elm_t A, A24, C24, C, zero, one, PK0, PK1, PK2, t0, t1;
    digit_t a0[NWORDS_ORDER], b0[NWORDS_ORDER], a1[NWORDS_ORDER], b1[NWORDS_ORDER];
    uint64_t Montgomery_rB[NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5};  // Value -(3^239)^-1 mod 2^384
	point_full_proj_t Q1, Q2, Q3, Q4;
	point_proj_t P1, P2, R;
    point_t R1, R2, R3, R4;
	PCurveIsogenyStruct CurveIsogeny = {0};
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	bool passed;

	// Allocating memory for private keys, public keys and shared secrets
	// Do this to obtain "random" curves.
	PrivateKeyA = (unsigned char*)calloc(1, obytes);                   // One element in [1, order]  
	PrivateKeyB = (unsigned char*)calloc(1, obytes);
	PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);                // Four elements in GF(p^2)
	PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);
	CompressedPKA = (unsigned char*)calloc(1, 3*obytes + 2*pbytes);    // Three elements in [1, order] plus one field element
	CompressedPKB = (unsigned char*)calloc(1, 3*obytes + 2*pbytes);    
    SharedSecret1 = (unsigned char*)calloc(1, 2*pbytes);               // One element in GF(p^2)  
    SharedSecret2 = (unsigned char*)calloc(1, 2*pbytes);

	printf("\n--------------------------------------------------------------------------------------------------------\n\n");
	printf("Testing compression functions: \n\n");

	// Curve isogeny system initialization
	CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		OK = false;
		goto cleanup;
	}
	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
	if (Status != CRYPTO_SUCCESS) {
		OK = false;
		goto cleanup;
	}
    
	fp2zero751(zero);
	fp2zero751(one);
	fp2zero751(C);
	fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
	fpcopy751(one[0], C[0]);

	// Testing 2-torsion compression
	passed = 1;
	for (i = 0; i < COMP_TEST_LOOPS; i++)  
	{
		Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);      // Get some value as Alice's secret key and compute Alice's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		} 
		Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);      // Get some value as Bob's secret key and compute Bob's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}   
        Status = EphemeralSecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecret1, CurveIsogeny);  // Alice computes her shared secret using Bob's public key
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }  

		to_fp2mont(((f2elm_t*)PublicKeyB)[0], PK0);
		to_fp2mont(((f2elm_t*)PublicKeyB)[1], PK1);
		to_fp2mont(((f2elm_t*)PublicKeyB)[2], PK2);
		get_A(PK0, PK1, PK2, A, CurveIsogeny);
		fp2correction751(A);

		fpzero751(C24[1]);
		fpadd751(one[0], one[0], C24[0]);
		fp2add751(C24, A, A24);
		fpadd751(C24[0], C24[0], C24[0]);
		fp2inv751_mont_bingcd(C24);
		fp2mul751_mont(A24, C24, A24);

        compress_2_torsion(PublicKeyB, CompressedPKB, (uint64_t*)a0, (uint64_t*)b0, (uint64_t*)a1, (uint64_t*)b1, R1, R2, CurveIsogeny);    // Bob compresses his public key
        
        bit = CompressedPKB[3*obytes-1] >> 7;
        temp = CompressedPKB[3*obytes-1];
        CompressedPKB[3*obytes-1] &= (unsigned char)(-1) >> 1;

        if (bit == 0) {  
            // Test a0*(R1+comp[2]*R2) = +- phiP
		    // Compute affine difference point R3 = R1 - R2
			fp2copy751(R1->x, Q1->X);
			fp2copy751(R1->y, Q1->Y);
			fp2copy751(one, Q1->Z);
			fp2copy751(R2->x, Q2->X);
			fp2copy751(R2->y, Q2->Y);
			fp2neg751(Q2->Y);
			fp2copy751(one, Q2->Z);
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			// Compute R1 + comp[2]*R2
			ladder_3_pt(R1->x, R2->x, R3->x, (digit_t*)&CompressedPKB[0], ALICE, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			// Compute a0*(R1 + comp[2]*R2)
			Mont_ladder(R3->x, a0, P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
		 
            if (fp2compare751(R3->x, PK0) != 0) { printf("PK0\n"); passed = 0; break; }
            
            // Test a0*(comp[3]*R1+comp[4]*R2) = +- phiQ
			// Compute R1 <- comp[3]*R1
			Mont_ladder(R1->x, &((digit_t*)CompressedPKB)[NWORDS_ORDER], P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
		    fp2correction751(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R1->x);

		    // Recover y-coordinate, unique only up to sign
		    fp2copy751(R1->x, Q1->X);
		    fp2copy751(one, Q1->Z);
		    fp2mul751_mont(Q1->X, Q1->X, t0);
		    fp2mul751_mont(A, Q1->X, t1);
		    fp2add751(t0, t1, t0);
		    fp2mul751_mont(Q1->X, t0, t0);   
		    fp2add751(Q1->X, t0, t0);                           
		    fp2correction751(t0);
		    sqrt_Fp2(t0, Q1->Y);
		    fp2correction751(Q1->Y);        // Keeps Y
		    fp2copy751(Q1->Y, Q4->Y);
		    fp2neg751(Q4->Y);
		    fp2correction751(Q4->Y);        // Keeps -Y
		    fp2copy751(R1->x, Q4->X);
		    fp2copy751(one, Q4->Z);
		    // Compute affine difference point R3 = R1 - R2
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			fp2correction751(R3->x);
			// Compute R1 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R3->x, &((digit_t*)CompressedPKB)[2*NWORDS_ORDER], ALICE, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
			// Compute a0*(R1 + comp[4]*R2)
			Mont_ladder(R3->x, a0, P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
            
		    // Compute affine difference point R4 = R1 - R2
			ADD(Q4, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R4->x);
			fp2correction751(R4->x);
			// Compute R4 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R4->x, &((digit_t*)CompressedPKB)[2*NWORDS_ORDER], ALICE, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
			// Compute a0*(R4 + comp[4]*R2)
			Mont_ladder(R4->x, a0, P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
		 
            if (fp2compare751(R3->x, PK1) != 0 && fp2compare751(R4->x, PK1) != 0) { printf("PK1\n"); passed = 0; break; }

        } else {  // Test b0*(R2+comp[2]*R1) = +- phiP
		    // Compute affine difference point R3 = R1 - R2
			fp2copy751(R1->x, Q1->X);
			fp2copy751(R1->y, Q1->Y);
			fp2copy751(one, Q1->Z);
			fp2copy751(R2->x, Q2->X);
			fp2copy751(R2->y, Q2->Y);
			fp2neg751(Q2->Y);
			fp2copy751(one, Q2->Z);
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			// Compute R2 + comp[2]*R1
			ladder_3_pt(R2->x, R1->x, R3->x, (digit_t*)&CompressedPKB[0], ALICE, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			// Compute b0*(R2 + comp[2]*R1)
			Mont_ladder(R3->x, b0, P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
		 
            if (fp2compare751(R3->x, PK0) != 0) { printf("PK0\n"); passed = 0; break; }
            
            // Test a0*(comp[3]*R1+comp[4]*R2) = +- phiQ
			// Compute R1 <- comp[3]*R1
			Mont_ladder(R1->x, &((digit_t*)CompressedPKB)[NWORDS_ORDER], P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
		    fp2correction751(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R1->x);

		    // Recover y-coordinate, unique only up to sign
		    fp2copy751(R1->x, Q1->X);
		    fp2copy751(one, Q1->Z);
		    fp2mul751_mont(Q1->X, Q1->X, t0);
		    fp2mul751_mont(A, Q1->X, t1);
		    fp2add751(t0, t1, t0);
		    fp2mul751_mont(Q1->X, t0, t0);   
		    fp2add751(Q1->X, t0, t0);                           
		    fp2correction751(t0);
		    sqrt_Fp2(t0, Q1->Y);
		    fp2correction751(Q1->Y);        // Keeps Y
		    fp2copy751(Q1->Y, Q4->Y);
		    fp2neg751(Q4->Y);
		    fp2correction751(Q4->Y);        // Keeps -Y
		    fp2copy751(R1->x, Q4->X);
		    fp2copy751(one, Q4->Z);
		    // Compute affine difference point R3 = R1 - R2
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			fp2correction751(R3->x);
			// Compute R1 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R3->x, &((digit_t*)CompressedPKB)[2*NWORDS_ORDER], ALICE, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
			// Compute b0*(R1 + comp[4]*R2)
			Mont_ladder(R3->x, b0, P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
            
		    // Compute affine difference point R4 = R1 - R2
			ADD(Q4, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R4->x);
			fp2correction751(R4->x);
			// Compute R4 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R4->x, &((digit_t*)CompressedPKB)[2*NWORDS_ORDER], ALICE, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
			// Compute b0*(R4 + comp[4]*R2)
			Mont_ladder(R4->x, b0, P1, P2, A24, CurveIsogeny->oAbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
		 
            if (fp2compare751(R3->x, PK1) != 0 && fp2compare751(R4->x, PK1) != 0) { printf("PK1\n"); passed = 0; break; }
        }

        CompressedPKB[3*obytes-1] = temp;                                     // Restore top bit
        decompress_2_torsion(PrivateKeyA, CompressedPKB, R, A, CurveIsogeny);    // Alice decompresses Bob's public key data using her private key  

        Status = EphemeralSecretAgreement_Compression_A(PrivateKeyA, (unsigned char*)R, (unsigned char*)A, SharedSecret2, CurveIsogeny);    // Alice computes her shared secret using decompressed Bob's public key data
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }  
        
        if (compare_words((digit_t*)SharedSecret1, (digit_t*)SharedSecret2, NBYTES_TO_NWORDS(2*pbytes)) != 0) {
            passed = false;
            Status = CRYPTO_ERROR_SHARED_KEY;
            break;
        }
	}
	if (passed == 1) printf("  2-torsion compression/decompression tests.............................. PASSED");
	else { printf("  2-torsion compression/decompression tests... FAILED"); printf("\n"); return false; }
	printf("\n");


	// Testing 3-torsion compression
	passed = 1;
	for (i = 0; i < COMP_TEST_LOOPS; i++)  
	{
		Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);      // Get some value as Alice's secret key and compute Alice's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		} 
		Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);      // Get some value as Bob's secret key and compute Bob's public key
		if (Status != CRYPTO_SUCCESS) {
			OK = false;
			goto cleanup;
		}   
        Status = EphemeralSecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecret1, CurveIsogeny);  // Bob computes his shared secret using Alice's public key
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }

		to_fp2mont(((f2elm_t*)PublicKeyA)[0], PK0);
		to_fp2mont(((f2elm_t*)PublicKeyA)[1], PK1);
		to_fp2mont(((f2elm_t*)PublicKeyA)[2], PK2);
		get_A(PK0, PK1, PK2, A, CurveIsogeny);
		fp2correction751(A);

		fpzero751(C24[1]);
		fpadd751(one[0], one[0], C24[0]);
		fp2add751(C24, A, A24);
		fpadd751(C24[0], C24[0], C24[0]);
		fp2inv751_mont_bingcd(C24);
		fp2mul751_mont(A24, C24, A24);

        compress_3_torsion(PublicKeyA, CompressedPKA, (uint64_t*)a0, (uint64_t*)b0, (uint64_t*)a1, (uint64_t*)b1, R1, R2, CurveIsogeny);

        from_Montgomery_mod_order(a0, a0, CurveIsogeny->Border, (digit_t*)&Montgomery_rB);          
        from_Montgomery_mod_order(a1, a1, CurveIsogeny->Border, (digit_t*)&Montgomery_rB);
        from_Montgomery_mod_order(b0, b0, CurveIsogeny->Border, (digit_t*)&Montgomery_rB);
        from_Montgomery_mod_order(b1, b1, CurveIsogeny->Border, (digit_t*)&Montgomery_rB);
        
        bit = CompressedPKA[3*obytes-1] >> 7;
        temp = CompressedPKA[3*obytes-1];
        CompressedPKA[3*obytes-1] &= (unsigned char)(-1) >> 1;

        if (bit == 0) {  
            // Test a0*(R1+comp[2]*R2) = +- phiP
		    // Compute affine difference point R3 = R1 - R2
			fp2copy751(R1->x, Q1->X);
			fp2copy751(R1->y, Q1->Y);
			fp2copy751(one, Q1->Z);
			fp2copy751(R2->x, Q2->X);
			fp2copy751(R2->y, Q2->Y);
			fp2neg751(Q2->Y);
			fp2copy751(one, Q2->Z);
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			// Compute R1 + comp[2]*R2
			ladder_3_pt(R1->x, R2->x, R3->x, (digit_t*)&CompressedPKA[0], BOB, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			// Compute a0*(R1 + comp[2]*R2)
			Mont_ladder(R3->x, a0, P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
		 
            if (fp2compare751(R3->x, PK0) != 0) { printf("PK0\n"); passed = 0; break; }
            
            // Test a0*(comp[3]*R1+comp[4]*R2) = +- phiQ
			// Compute R1 <- comp[3]*R1
			Mont_ladder(R1->x, &((digit_t*)CompressedPKA)[NWORDS_ORDER], P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
		    fp2correction751(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R1->x);

		    // Recover y-coordinate, unique only up to sign
		    fp2copy751(R1->x, Q1->X);
		    fp2copy751(one, Q1->Z);
		    fp2mul751_mont(Q1->X, Q1->X, t0);
		    fp2mul751_mont(A, Q1->X, t1);
		    fp2add751(t0, t1, t0);
		    fp2mul751_mont(Q1->X, t0, t0);   
		    fp2add751(Q1->X, t0, t0);                           
		    fp2correction751(t0);
		    sqrt_Fp2(t0, Q1->Y);
		    fp2correction751(Q1->Y);        // Keeps Y
		    fp2copy751(Q1->Y, Q4->Y);
		    fp2neg751(Q4->Y);
		    fp2correction751(Q4->Y);        // Keeps -Y
		    fp2copy751(R1->x, Q4->X);
		    fp2copy751(one, Q4->Z);
		    // Compute affine difference point R3 = R1 - R2
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			fp2correction751(R3->x);
			// Compute R1 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R3->x, &((digit_t*)CompressedPKA)[2*NWORDS_ORDER], BOB, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
			// Compute a0*(R1 + comp[4]*R2)
			Mont_ladder(R3->x, a0, P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
            
		    // Compute affine difference point R4 = R1 - R2
			ADD(Q4, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R4->x);
			fp2correction751(R4->x);
			// Compute R4 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R4->x, &((digit_t*)CompressedPKA)[2*NWORDS_ORDER], BOB , P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
			// Compute a0*(R4 + comp[4]*R2)
			Mont_ladder(R4->x, a0, P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
		 
            if (fp2compare751(R3->x, PK1) != 0 && fp2compare751(R4->x, PK1) != 0) { printf("PK1\n"); passed = 0; break; }

        } else {  // Test b0*(R2+comp[2]*R1) = +- phiP
		    // Compute affine difference point R3 = R1 - R2
			fp2copy751(R1->x, Q1->X);
			fp2copy751(R1->y, Q1->Y);
			fp2copy751(one, Q1->Z);
			fp2copy751(R2->x, Q2->X);
			fp2copy751(R2->y, Q2->Y);
			fp2neg751(Q2->Y);
			fp2copy751(one, Q2->Z);
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			// Compute R2 + comp[2]*R1
			ladder_3_pt(R2->x, R1->x, R3->x, (digit_t*)&CompressedPKA[0], BOB, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			// Compute b0*(R2 + comp[2]*R1)
			Mont_ladder(R3->x, b0, P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
		 
            if (fp2compare751(R3->x, PK0) != 0) { printf("PK0\n"); passed = 0; break; }
            
            // Test a0*(comp[3]*R1+comp[4]*R2) = +- phiQ
			// Compute R1 <- comp[3]*R1
			Mont_ladder(R1->x, &((digit_t*)CompressedPKA)[NWORDS_ORDER], P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
		    fp2correction751(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R1->x);

		    // Recover y-coordinate, unique only up to sign
		    fp2copy751(R1->x, Q1->X);
		    fp2copy751(one, Q1->Z);
		    fp2mul751_mont(Q1->X, Q1->X, t0);
		    fp2mul751_mont(A, Q1->X, t1);
		    fp2add751(t0, t1, t0);
		    fp2mul751_mont(Q1->X, t0, t0);   
		    fp2add751(Q1->X, t0, t0);                           
		    fp2correction751(t0);
		    sqrt_Fp2(t0, Q1->Y);
		    fp2correction751(Q1->Y);        // Keeps Y
		    fp2copy751(Q1->Y, Q4->Y);
		    fp2neg751(Q4->Y);
		    fp2correction751(Q4->Y);        // Keeps -Y
		    fp2copy751(R1->x, Q4->X);
		    fp2copy751(one, Q4->Z);
		    // Compute affine difference point R3 = R1 - R2
			ADD(Q1, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R3->x);
			fp2correction751(R3->x);
			// Compute R1 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R3->x, &((digit_t*)CompressedPKA)[2*NWORDS_ORDER], BOB, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
			// Compute b0*(R1 + comp[4]*R2)
			Mont_ladder(R3->x, b0, P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R3->x);
			fp2correction751(R3->x);
            
		    // Compute affine difference point R4 = R1 - R2
			ADD(Q4, Q2->X, Q2->Y, Q2->Z, A, Q3);
			fp2inv751_mont_bingcd(Q3->Z);
			fp2mul751_mont(Q3->X, Q3->Z, R4->x);
			fp2correction751(R4->x);
			// Compute R4 + comp[4]*R2
			ladder_3_pt(R1->x, R2->x, R4->x, &((digit_t*)CompressedPKA)[2*NWORDS_ORDER], BOB, P1, A, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
			// Compute b0*(R4 + comp[4]*R2)
			Mont_ladder(R4->x, b0, P1, P2, A24, CurveIsogeny->oBbits, CurveIsogeny->owordbits, CurveIsogeny);
			fp2inv751_mont_bingcd(P1->Z);
			fp2mul751_mont(P1->X, P1->Z, R4->x);
			fp2correction751(R4->x);
		 
            if (fp2compare751(R3->x, PK1) != 0 && fp2compare751(R4->x, PK1) != 0) { printf("PK1\n"); passed = 0; break; }
        }
        
        CompressedPKA[3*obytes-1] = temp;                                        // Restore top bit
        decompress_3_torsion(PrivateKeyB, CompressedPKA, R, A, CurveIsogeny);    // Bob decompresses Alice's public key data using his private key  

        Status = EphemeralSecretAgreement_Compression_B(PrivateKeyB, (unsigned char*)R, (unsigned char*)A, SharedSecret2, CurveIsogeny);    // Bob computes his shared secret using the decompressed Alice's public key data
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }  
        
        if (compare_words((digit_t*)SharedSecret1, (digit_t*)SharedSecret2, NBYTES_TO_NWORDS(2*pbytes)) != 0) {
            passed = false;
            Status = CRYPTO_ERROR_SHARED_KEY;
            break;
        }        
	}
	if (passed == 1) printf("  3-torsion compression tests............................................ PASSED");
	else { printf("  3-torsion compression tests... FAILED"); printf("\n"); return false; }
	printf("\n");

cleanup:
	SIDH_curve_free(CurveIsogeny);   
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);   
    free(CompressedPKA);    
    free(CompressedPKB);    
    free(SharedSecret1);    
    free(SharedSecret2);

	return OK;
}


int main()
{
    bool OK = true;

    OK = OK && fp_test();        // Test field operations using p751
    OK = OK && fp_run();         // Benchmark field operations using p751

    OK = OK && fp2_test();       // Test arithmetic functions over GF(p751^2)
    OK = OK && fp2_run();        // Benchmark arithmetic functions over GF(p751^2)
    
    OK = OK && ecisog_run(&CurveIsogeny_SIDHp751);       // Benchmark elliptic curve and isogeny functions

    OK = OK && ecpoints_test(&CurveIsogeny_SIDHp751);    // Test point generation functions
    OK = OK && ecpairing_test(&CurveIsogeny_SIDHp751);   // Test pairing functions
    OK = OK && ecph_test(&CurveIsogeny_SIDHp751);        // Test Pohlig-Hellman functions    
    OK = OK && eccompress_test(&CurveIsogeny_SIDHp751);  // Test Pohlig-Hellman functions

    return OK;
}
