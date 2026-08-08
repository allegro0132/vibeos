// M3 acceptance: allocate from the granted region, sort it, print it.
fn main() {
    let mut a: [i64; 12] = [0; 12];
    // A deterministic scramble, so the input is not already ordered.
    let mut i = 0;
    let mut v: i64 = 0;
    while i < 12 {
        a[i] = (v * 7919) % 101 - 50;
        v = v + 1;
        i = i + 1;
    }

    print!("before");
    i = 0;
    while i < 12 {
        print!(" {}", a[i]);
        i = i + 1;
    }
    println!("");

    // Insertion sort, in place.
    let mut n = 1;
    while n < 12 {
        let key: i64 = a[n];
        let mut j = n;
        while j > 0 && a[j - 1] > key {
            a[j] = a[j - 1];
            j = j - 1;
        }
        a[j] = key;
        n = n + 1;
    }

    print!("after");
    i = 0;
    while i < 12 {
        print!(" {}", a[i]);
        i = i + 1;
    }
    println!("");

    let mut sorted = true;
    i = 1;
    while i < 12 {
        if a[i - 1] > a[i] {
            sorted = false;
        }
        i = i + 1;
    }
    println!("sorted {}", sorted);
}
