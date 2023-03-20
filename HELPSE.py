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
import sys
from LPSE import average_strength_value, pass_vector
from math import comb, log2



#def FHE_context() -> tuple[Encryptor, Evaluator, Decryptor, bytes]:
parms = EncryptionParameters(scheme_type.ckks)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))
# parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
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

    #return context, encryptor, evaluator, decryptor, encoder, relin_keys, scale
def print_vector(vector):
    print('[ ', end='')
    for i in range(0, 8):
        print(vector[i], end=', ')
    print('... ]')

def int_to_hex(numbers: list[int]) -> str:
    if isinstance(numbers, int):
        numbers = [numbers]
    return ''.join('{:02X}'.format(a) for a in numbers)

def step_func(a, n_c = 4):
    sigma_j = []
    for j in range(n_c):
        k = 1/4**j * comb(2*j,j)
        if j == 0:
            b = evaluator.multiply_plain(a, encoder.encode(float(k), scale))
            sigma_j.append(b)
            continue

        a_squared = evaluator.square(a)
        a_squared_minus = evaluator.negate(a_squared)
        b = evaluator.add_plain(a_squared_minus, Plaintext('1'))
        if j>1:
            b = evaluator.exponentiate(b, Plaintext(str(j)))
        b = evaluator.multiply(a, b)
        b = evaluator.multiply_plain(b, Plaintext(str(k)))
        sigma_j.append(b)
    return evaluator.add_many(sigma_j)

def he_compare(encrypted_x, encrypted_y, n_c = 4, d_c =4):
    a =evaluator.sub(encrypted_x, encrypted_y)
    for i in range(d_c):
        a = step_func(a)
    a = evaluator.add_plain(a, Plaintext('1'))
    a = evaluator.multiply_plain(a, Plaintext('0.5'))
    return a

def he_invert(encrypted_value, iterations=5):
    x_neg = evaluator.negate(encrypted_value)
    a = evaluator.add_plain(x_neg, Plaintext('2'))
    b = evaluator.add_plain(x_neg, Plaintext('1'))
    for i in range(iterations):
        b = evaluator.square(b)
        a = evaluator.multiply(a, evaluator.add_plain(b, Plaintext('1')))
    return a

def he_max(x,y):
    _max = evaluator.add(x,y)
    diff = evaluator.sub(x,y)
    diff_sq = evaluator.square(diff)
    diff_len = he_sqrt(diff_sq)
    _max = evaluator.add(_max, diff_len)
    return evaluator.multiply_plain(_max, Plaintext('0.5'))

def he_min(x,y):
    _max = evaluator.add(x,y)
    diff = evaluator.sub(x,y)
    diff_sq = evaluator.square(diff)
    diff_len = he_sqrt(diff_sq)
    _max = evaluator.sub(_max, diff_len)
    return evaluator.multiply_plain(_max, Plaintext('0.5'))

def he_sqrt(x, iterations=5):
    a = x
    p_05 = encoder.encode(0.5, scale)
    p_1 = encoder.encode(1.0, scale)
    p_3 = encoder.encode(3.0, scale)
    b = evaluator.sub_plain(x, encoder.encode(1.0, scale))
    for _ in range(iterations):
        b_half = evaluator.multiply_plain(evaluator.negate(b), p_05)
        evaluator.relinearize_inplace(b_half, relin_keys)
        evaluator.rescale_to_next_inplace(b_half)
        minus_b_half = evaluator.add_plain(b_half, p_1)
        a = evaluator.multiply(a,minus_b_half)
        b = evaluator.multiply(evaluator.square(b), evaluator.sub_plain(b, p_3))
        b = evaluator.multiply_plain(b, Plaintext('0.25'))
    return a

def HELPSE(password: str) -> tuple[float, str]:
    # context, encryptor, evaluator, decryptor, encoder, relin_keys, scale = FHE_context()
    slot_count = encoder.slot_count()

    data = [3.1415926] * slot_count
    plain = encoder.encode(data, scale)
    cipher = encryptor.encrypt(plain)
    row_size = slot_count // 2
    print(f'Plaintext matrix row size: {row_size}')

    p_1 = encoder.encode(3.14, scale)
    e_1 = encryptor.encrypt(p_1)

    p_3 = encoder.encode(3.0, scale)
    e_x = evaluator.multiply_plain(e_1, p_3)

    x = encryptor.encrypt(encoder.encode(9.0,scale))
    ex_ = he_sqrt(x)

    p_x = decryptor.decrypt(e_x)
    m_x = encoder.decode(p_x)
   


    enc_passvector = []
    for i, value in enumerate(pass_vector(password=password)):
        p = encoder.encode(float(value), scale)
        enc_passvector.append(encryptor.encrypt(p))
    

def print_parameters(context):
    context_data = context.key_context_data()
    if context_data.parms().scheme() == scheme_type.bfv:
        scheme_name = 'bfv'
    elif context_data.parms().scheme() == scheme_type.ckks:
        scheme_name = 'ckks'
    else:
        scheme_name = 'none'
    print('/')
    print('| Encryption parameters')
    print('| scheme: ' + scheme_name)
    print(f'| poly_modulus_degree: {context_data.parms().poly_modulus_degree()}')
    coeff_modulus = context_data.parms().coeff_modulus()
    coeff_modulus_sum = 0
    for j in coeff_modulus:
        coeff_modulus_sum += j.bit_count()
    print(f'| coeff_modulus size: {coeff_modulus_sum}(', end='')
    for i in range(len(coeff_modulus) - 1):
        print(f'{coeff_modulus[i].bit_count()} + ', end='')
    print(f'{coeff_modulus[-1].bit_count()}) bits')
    if context_data.parms().scheme() == scheme_type.bfv:
        print(f'| plain_modulus: {context_data.parms().plain_modulus().value()}')
    print('\\')


if __name__ == '__main__':
    print(HELPSE(sys.argv[1]))
