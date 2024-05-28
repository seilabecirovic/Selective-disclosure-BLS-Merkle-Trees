
export function closestPowerOfTwo(n) {
    if (n < 1) return 1;
    let power = 1;
    while (power < n) {
        power *= 2;
    }
    return power;
  }
export function stringToBigInt(str) {
    let result = '0x';
    for (let i = 0; i < str.length; i++) {
        // Convert each character to a hexadecimal code and append
        result += str.charCodeAt(i).toString(16);
    }
    return BigInt(result);
  }
