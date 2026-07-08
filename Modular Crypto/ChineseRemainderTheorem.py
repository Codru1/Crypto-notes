def find_min_x(nums, rems):
   # Initialize result
    x = 1 

    while True:
        # Check if remainder of x % nums[j] is rem[j] for all j from 0 to k-1
        for j in range(len(nums)):
            if x % nums[j] != rems[j]:
                break

        # If all remainders matched, we found x
        if j == len(nums) - 1:
            return x

        # Else, try the next number
        x += 1

    return x

# Example Usage
nums = [3, 4, 5]
rems = [2, 3, 1]
print(find_min_x(nums, rems))
