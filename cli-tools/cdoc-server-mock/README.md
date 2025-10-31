# CDOC2 Key Server Mock

A standalone HTTP server that implements the CDOC2 key server API for testing purposes.

## Usage

### Run the server

```bash
cd cli-tools/cdoc-server-mock
go run main.go
```

Or build and run:

```bash
cd cli-tools/cdoc-server-mock
go build -o cdoc-server-mock
./cdoc-server-mock
```

### Configuration

The server listens on port 8080 by default. You can change the port by setting the `PORT` environment variable:

```bash
PORT=8443 go run main.go
```

## API Endpoints

### POST /key-capsules

Stores a key capsule and returns a transaction ID.

**Request Body:**
```json
{
  "recipient_id": "base64-encoded-recipient-key",
  "ephemeral_key_material": "base64-encoded-key-material",
  "capsule_type": "RSA" or "ecc_secp384r1"
}
```

**Optional Headers:**
- `x-expiry-time`: RFC3339 formatted expiry time

**Response:**
- Status: 201 Created
- Headers:
  - `Location: http://localhost:8080/key-capsules/{transaction_id}`
  - `x-expiry-time`: (if provided in request)

### GET /key-capsules/{transaction_id}

Retrieves a stored key capsule.

**Response:**
```json
{
  "ephemeral_key_material": "base64-encoded-key-material"
}
```

**Status Codes:**
- 200 OK: Key capsule found and returned
- 404 Not Found: Transaction ID not found
- 410 Gone: Transaction expired

## Example

```bash
# Start the server
go run main.go

# In another terminal, store a key capsule
curl -X POST http://localhost:8080/key-capsules \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": "dGVzdA==",
    "ephemeral_key_material": "dGVzdA==",
    "capsule_type": "RSA"
  }'

# Retrieve the key capsule (use transaction_id from Location header)
curl http://localhost:8080/key-capsules/{transaction_id}
```

