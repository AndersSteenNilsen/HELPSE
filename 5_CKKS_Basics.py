from seal import (
    EncryptionParameters,
    scheme_type,
    CoeffModulus,
    PlainModulus,
    SEALContext,
    KeyGenerator,
    Encryptor,
    Evaluator,
    Decryptor,
    BatchEncoder,
    CKKSEncoder,
    Ciphertext,
    Plaintext,
)

from math import log2


def print_vector(vector, rows, cols):
    print('[')
    for r in range(rows):
        print(*vector[r*cols:(r+1)*cols], sep='\t')
    print(']')

# In this example we demonstrate evaluating a polynomial function

#     PI*x^3 + 0.4*x + 1

# on encrypted floating-point input data x for a set of 4096 equidistant points
# in the interval [0, 1]. This example demonstrates many of the main features
# of the CKKS scheme, but also the challenges in using it.

# We start by setting up the CKKS scheme.

parms = EncryptionParameters(scheme_type.ckks)
poly_modulus_degree = 2**13
parms.set_poly_modulus_degree(poly_modulus_degree)
p = [60, 40, 40, 60]  # P_0, P_1, P_2, P_3
parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, p))

context = SEALContext(parms)
encoder = CKKSEncoder(context)
scale = 2.0 ** 40

keygen = KeyGenerator(context)
secret_key = keygen.secret_key()
public_key = keygen.create_public_key()
relin_keys = keygen.create_relin_keys()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

print(f'{encoder.slot_count()}')

x_vector = [float(i) for i in range(encoder.slot_count())]

pi_def = 3.14
plain_π = encoder.encode(pi_def, scale)
plain_04 = encoder.encode(0.4, scale)
plain_1 = encoder.encode(1.0, scale)

x_encoded = encoder.encode(x_vector, scale)
x_1_encrypted = encryptor.encrypt(x_encoded)
print(f'{log2(x_1_encrypted.scale())=}')

# To compute x^3 we first compute x^2 and relinearize.
# However, the scale has now grown to 2^80.
print('Compute x^2 and relinearize')
x_2_encrypted = evaluator.square(x_1_encrypted)
evaluator.relinearize_inplace(x_2_encrypted, relin_keys)
print(f'{log2(x_2_encrypted.scale())=}')


# Now rescale; in addition to a modulus switch, the scale is reduced down by
# a factor equal to the prime that was switched away (40-bit prime). Hence, the
# new scale should be close to 2^40. Note, however, that the scale is not equal
# to 2^40: this is because the 40-bit prime is only close to 2^40.
print('Rescale x^2')
evaluator.rescale_to_next_inplace(x_2_encrypted)
print(f'{log2(x_2_encrypted.scale())=} After rescale')


# Now x_2_encrypted is at a different level than x_1_encrypted, which prevents us
# from multiplying them to compute x^3. We could simply switch x_1_encrypted to
# the next parameters in the modulus switching chain. However, since we still
# need to multiply the x^3 term with PI (plainCoeff3), we instead compute PI*x
# first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
# PI*x and rescale it back from scale 2^80 to something close to 2^40.

print('Compute and rescale π*x')
x_π_encrypted = evaluator.multiply_plain(x_1_encrypted, plain_π)
print(f'{log2(x_π_encrypted.scale())=}')
evaluator.rescale_to_next_inplace(x_π_encrypted)
print(f'{log2(x_π_encrypted.scale())=} after rescale')

# Since x_2_encrypted and x_π_encrypted have the same exact scale and use
# the same encryption parameters, we can multiply them together. We write the
# result to x_2_encrypted, relinearize, and rescale. Note that again the scale
# is something close to 2^40, but not exactly 2^40 due to yet another scaling
# by a prime. We are down to the last level in the modulus switching chain.

print('Compute, relinearize, and rescale (π*x)*(x^2).')
x_π_3_encrypted = evaluator.multiply(x_π_encrypted, x_2_encrypted)
evaluator.relinearize_inplace(x_π_3_encrypted, relin_keys)
print(f'{log2(x_π_3_encrypted.scale())=}')
evaluator.rescale_to_next_inplace(x_π_3_encrypted)
print(f'{log2(x_π_3_encrypted.scale())=} After rescale')

#DEBUG

print('x^2 OK')
p_x2 = decryptor.decrypt(x_2_encrypted)
r_x2 = encoder.decode(p_x2)
print_vector(r_x2, 3, 7)

print('pi*x ok')
p_xpi = decryptor.decrypt(x_π_encrypted)
r_xpi = encoder.decode(p_xpi)
print_vector(r_xpi, 3, 7)

print('pi*x^3, not ok')
p_xpi3 = decryptor.decrypt(x_π_3_encrypted)
r_xpi3 = encoder.decode(p_xpi3)
print_vector(r_xpi3, 3, 7)
#DEBUG

# Next we compute the degree one term. All this requires is one MultiplyPlain
# with plainCoeff1. We overwrite x1Encrypted with the result.

print('Compute and rescale 0.4*x')
x_04_1_encrypted = evaluator.multiply_plain(x_1_encrypted, plain_04)
print(f'{log2(x_04_1_encrypted.scale())=}')
evaluator.rescale_to_next_inplace(x_04_1_encrypted)
print(f'{log2(x_04_1_encrypted.scale())=} After rescale.')

# Now we would hope to compute the sum of all three terms. However, there is
# a serious problem: the encryption parameters used by all three terms are
# different due to modulus switching from rescaling.

# Encrypted addition and subtraction require that the scales of the inputs are
# the same, and also that the encryption parameters (ParmsId) match. If there
# is a mismatch, Evaluator will throw an exception.
print(f'{context.get_context_data(x_π_3_encrypted.parms_id()).chain_index()=}')
print(f'{context.get_context_data(x_04_1_encrypted.parms_id()).chain_index()=}')
print(f'{context.get_context_data(plain_1.parms_id()).chain_index()=}')

# Let us carefully consider what the scales are at this point. We denote the
# primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
# the special modulus and is not involved in rescalings. After the computations
# above the scales in ciphertexts are:

#     - Product x^2 has scale 2^80 and is at level 2;
#     - Product PI*x has scale 2^80 and is at level 2;
#     - We rescaled both down to scale 2^80/P2 and level 1;
#     - Product PI*x^3 has scale (2^80/P_2)^2;
#     - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
#     - Product 0.4*x has scale 2^80;
#     - We rescaled it down to scale 2^80/P_2 and level 1;
#     - The contant term 1 has scale 2^40 and is at level 2.

# Although the scales of all three terms are approximately 2^40, their exact
# values are different, hence they cannot be added together.

print(f'{log2(x_π_3_encrypted.scale())=}')
print(f'{log2(x_04_1_encrypted.scale())=}')
print(f'{log2(plain_1.scale())=}')

# There are many ways to fix this problem. Since P_2 and P_1 are really close
# to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
# same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
# scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
# This should not result in any noticeable error.

# Another option would be to encode 1 with scale 2^80/P_2, do a MultiplyPlain
# with 0.4*x, and finally rescale. In this case we would need to additionally
# make sure to encode 1 with appropriate encryption parameters (ParmsId).

# In this example we will use the first (simplest) approach and simply change
# the scale of PI*x^3 and 0.4*x to 2^40.
print('Normalize scales to 2^40')
x_π_3_encrypted.scale(2**40)
x_04_1_encrypted.scale(2**40)

# We still have a problem with mismatching encryption parameters. This is easy
# to fix by using traditional modulus switching (no rescaling). CKKS supports
# modulus switching just like the BFV scheme, allowing us to switch away parts
# of the coefficient modulus when it is simply not needed.
print('Normalize encryption parameters to the lowest level.')
last_parms_id = x_π_3_encrypted.parms_id()
print(f'{last_parms_id=}')
evaluator.mod_switch_to_inplace(x_04_1_encrypted, last_parms_id)
evaluator.mod_switch_to_inplace(plain_1, last_parms_id)

# All three ciphertexts are now compatible and can be added.
print('Compute PI*x^3 + 0.4*x + 1.')
sum_encrypted = evaluator.add(x_04_1_encrypted, x_π_3_encrypted)
sum_encrypted = evaluator.add_plain(x_04_1_encrypted, plain_1)

# First print the true result.
print('expected:')
expected = [pi_def*x**3 + 0.4*x + 1 for x in x_vector]
print_vector(expected, 3, 7)



# We decrypt, decode, and print the result.
print('Actual/FHE calculated:')
plain_result = decryptor.decrypt(sum_encrypted)
result = encoder.decode(plain_result)
print_vector(result, 3, 7)

