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
    Ciphertext,
    Plaintext,
)
import sys
from LPSE import average_strength_value, pass_vector
from math import comb

def print_vector(vector):
    print('[ ', end='')
    for i in range(0, 8):
        print(vector[i], end=', ')
    print('... ]')


def FHE_context() -> tuple[Encryptor, Evaluator, Decryptor, bytes]:
    parms = EncryptionParameters(scheme_type.bgv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
    context = SEALContext(parms)

    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()
    relin_keys = keygen.create_relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    batch_encoder = BatchEncoder(context)

    return context, encryptor, evaluator, decryptor, batch_encoder, relin_keys

def int_to_hex(numbers: list[int]) -> str:
    if isinstance(numbers, int):
        numbers = [numbers]
    return ''.join('{:02X}'.format(a) for a in numbers)

def step_func(a, evaluator:Evaluator, n_c = 4):
    sigma_j = []
    for j in range(n_c):
        k = 1/4**j * comb(2*j,j)
        if j == 0:
            b = evaluator.multiply_plain(a, Plaintext(str(k)))
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

def he_compare(encrypted_x, encrypted_y, evaluator: Evaluator, n_c = 4, d_c =4):
    a =evaluator.sub(encrypted_x, encrypted_y)
    for i in range(d_c):
        a = step_func(a)
    a = evaluator.add_plain(a, Plaintext('1'))
    a = evaluator.multiply_plain(a, Plaintext('0.5'))
    return a

def he_invert(encrypted_value, evaluator: Evaluator, iterations=5):
    x_neg = evaluator.negate(encrypted_value)
    a = evaluator.add_plain(x_neg, Plaintext('2'))
    b = evaluator.add_plain(x_neg, Plaintext('1'))
    for i in range(iterations):
        b = evaluator.square(b)
        a = evaluator.multiply(a, evaluator.add_plain(b, Plaintext('1')))
    return a

def he_max(x,y, evaluator: Evaluator):
    _max = evaluator.add(x,y)
    diff = evaluator.sub(x,y)
    diff_sq = evaluator.square(diff)
    diff_len = he_sqrt(diff_sq)
    _max = evaluator.add(_max, diff_len)
    return evaluator.multiply_plain(_max, Plaintext('0.5'))

def he_min(x,y, evaluator: Evaluator):
    _max = evaluator.add(x,y)
    diff = evaluator.sub(x,y)
    diff_sq = evaluator.square(diff)
    diff_len = he_sqrt(diff_sq)
    _max = evaluator.sub(_max, diff_len)
    return evaluator.multiply_plain(_max, Plaintext('0.5'))

def he_sqrt(x, iterations=5, evaluator: Evaluator):
    a = x
    b = evaluator.sub_plain(x, Plaintext('1'))
    for _ in range(iterations):
        minus_b_half = evaluator.add_plain( evaluator.multiply_plain(evaluator.negate(b), Plaintext('0.5')), Plaintext('1'))
        a = evaluator.multiply(a,minus_b_half)
        b = evaluator.multiply(evaluator.square(b), evaluator.sub_plain(b,Plaintext('3')))
        b = evaluator.multiply_plain(b, Plaintext('0.25'))
    return a

def HELPSE(password: str) -> tuple[float, str]:
    context, encryptor, evaluator, decryptor, batch_encoder, relin_keys = FHE_context()
    slot_count = batch_encoder.slot_count()
    row_size = slot_count // 2
    print(f'Plaintext matrix row size: {row_size}')

    pt = Plaintext('1x^2 + 2x^1 + 3')

    value1 = 31*10
    value2 = 32*10
    assertions_ans = value1+value2
    
    
    plain1 = Plaintext(int_to_hex(value1))
    plain2 = Plaintext(int_to_hex(value2))

    # Encrypting the values is easy.
    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()
    print("Encrypting plain1: ")
    encrypted1 = encryptor.encrypt(plain1)
    print("Done (encrypted1)")

    print("Encrypting plain2: ")
    encrypted2 = encryptor.encrypt(plain2)
    print("Done (encrypted2)")

    # To illustrate the concept of noise budget, we print the budgets in the fresh
    # encryptions.
    print("Noise budget in encrypted1: " + (str)(decryptor.invariant_noise_budget(encrypted1)) + " bits")
    print("Noise budget in encrypted2: " + (str)(decryptor.invariant_noise_budget(encrypted2)) + " bits")
    x_added = evaluator.add(encrypted1, encrypted2)
    pow
    decrypted_result = decryptor.decrypt(x_added)
    decoded_result = batch_encoder.decode(decrypted_result)

    
    slots = [0] * slot_count
    for i, value in enumerate(pass_vector(password=password)):
        slots[i] = value
    slots[:4] = pass_vector(password=password)
    encoded_slots = batch_encoder.encode(slots)
    encrypted_slots = encryptor.encrypt(encoded_slots)


    # Can delete below this...
    pod_matrix[0] = value1
    pod_matrix[row_size] = value2




def example_bgv_basics():
    parms = EncryptionParameters(scheme_type.bgv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
    context = SEALContext(parms)

    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()
    relin_keys = keygen.create_relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    batch_encoder = BatchEncoder(context)
    slot_count = batch_encoder.slot_count()
    row_size = slot_count / 2
    print(f'Plaintext matrix row size: {row_size}')

    pod_matrix = [0] * slot_count
    pod_matrix[0] = 1
    pod_matrix[1] = 2
    pod_matrix[2] = 3
    pod_matrix[3] = 4

    x_plain = batch_encoder.encode(pod_matrix)

    x_encrypted = encryptor.encrypt(x_plain)
    print(
        f'noise budget in freshly encrypted x: {decryptor.invariant_noise_budget(x_encrypted)}'
    )
    print('-' * 50)

    x_squared = evaluator.square(x_encrypted)
    print(f'size of x_squared: {x_squared.size()}')
    evaluator.relinearize_inplace(x_squared, relin_keys)
    print(f'size of x_squared (after relinearization): {x_squared.size()}')
    print(
        f'noise budget in x_squared: {decryptor.invariant_noise_budget(x_squared)} bits'
    )
    decrypted_result = decryptor.decrypt(x_squared)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-' * 50)

    x_4th = evaluator.square(x_squared)
    print(f'size of x_4th: {x_4th.size()}')
    evaluator.relinearize_inplace(x_4th, relin_keys)
    print(f'size of x_4th (after relinearization): { x_4th.size()}')
    print(f'noise budget in x_4th: {decryptor.invariant_noise_budget(x_4th)} bits')
    decrypted_result = decryptor.decrypt(x_4th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-' * 50)

    x_8th = evaluator.square(x_4th)
    print(f'size of x_8th: {x_8th.size()}')
    evaluator.relinearize_inplace(x_8th, relin_keys)
    print(f'size of x_8th (after relinearization): { x_8th.size()}')
    print(f'noise budget in x_8th: {decryptor.invariant_noise_budget(x_8th)} bits')
    decrypted_result = decryptor.decrypt(x_8th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('run out of noise budget')
    print('-' * 100)

    x_encrypted = encryptor.encrypt(x_plain)
    print(
        f'noise budget in freshly encrypted x: {decryptor.invariant_noise_budget(x_encrypted)}'
    )
    print('-' * 50)

    x_squared = evaluator.square(x_encrypted)
    print(f'size of x_squared: {x_squared.size()}')
    evaluator.relinearize_inplace(x_squared, relin_keys)
    evaluator.mod_switch_to_next_inplace(x_squared)
    print(
        f'noise budget in x_squared (with modulus switching): {decryptor.invariant_noise_budget(x_squared)} bits'
    )
    decrypted_result = decryptor.decrypt(x_squared)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-' * 50)

    x_4th = evaluator.square(x_squared)
    print(f'size of x_4th: {x_4th.size()}')
    evaluator.relinearize_inplace(x_4th, relin_keys)
    evaluator.mod_switch_to_next_inplace(x_4th)
    print(f'size of x_4th (after relinearization): { x_4th.size()}')
    print(
        f'noise budget in x_4th (with modulus switching): {decryptor.invariant_noise_budget(x_4th)} bits'
    )
    decrypted_result = decryptor.decrypt(x_4th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-' * 50)

    x_8th = evaluator.square(x_4th)
    print(f'size of x_8th: {x_8th.size()}')
    evaluator.relinearize_inplace(x_8th, relin_keys)
    evaluator.mod_switch_to_next_inplace(x_8th)
    print(f'size of x_8th (after relinearization): { x_8th.size()}')
    print(
        f'noise budget in x_8th (with modulus switching): {decryptor.invariant_noise_budget(x_8th)} bits'
    )
    decrypted_result = decryptor.decrypt(x_8th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)

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
