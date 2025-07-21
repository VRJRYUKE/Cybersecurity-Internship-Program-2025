# Graylog Queries

## Basic Queries

1. **Search for specific log messages**
   ```
   message:"error"
   ```

2. **Filter by source IP**
   ```
   source_ip:192.168.1.1
   ```

3. **Search for logs within a specific time range**
   ```
   timestamp:[now-1h TO now]
   ```

## Advanced Queries

1. **Combine multiple conditions**
   ```
   message:"failed login" AND source_ip:192.168.1.1
   ```

2. **Use wildcards for partial matches**
   ```
   message:"*failed*"
   ```

3. **Group conditions using parentheses**
   ```
   (source_ip:192.168.1.1 OR source_ip:10.0.0.1) AND message:"error"
   ```

## Aggregation Queries

1. **Count occurrences of a specific message**
   ```
   count(message:"error")
   ```

2. **Group by source IP and count**
   ```
   groupby(source_ip, count())
   ```

## Useful Functions

1. **Top values for a field**
   ```
   top(source_ip, 10)
   ```

2. **Time series analysis**
   ```
   timeslice(1m, count())
   ```

## Example Queries

1. **Find all login attempts**
   ```
   message:"login"
   ```

2. **Identify unusual traffic patterns**
   ```
   source_ip:192.168.1.* AND timestamp:[now-1d TO now]
   ```

## Tips

- Always test your queries to ensure they return the expected results.
- Use the Graylog documentation for more advanced query syntax and examples.