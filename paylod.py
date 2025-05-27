import pickle
import base64

class DisplayData:
    def __reduce__(self):
        data = {"name": "Injected Name", "email": "injected@example.com", "role": "Injected Role"}  # Create a dictionary with the expected keys
        return display_data, (data,)

def display_data(data):
    print(f"[VULNERABILITY DEMO] Data to display: {data}")
    return data

serialized_payload = base64.b64encode(pickle.dumps(DisplayData())).decode()
print(serialized_payload)