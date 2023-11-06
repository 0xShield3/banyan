## All About Policies
### Anatomy of a Policy
#### Banyan Policy Language
Banyan is an adaptation of [AWS' Cedar Policy Language (CPL)](https://github.com/ipatka/banyan). Banyan adapts CPL for use in EVM transaction permissioning. You can get a firm understanding on the [cedar policy language in this tutorial.](https://www.cedarpolicy.com/en/tutorial/policy-structure) A CPL policy statement is made up of the following:
- The effect (forbid, permit)
- The scope (principal, action, resource)
- Conditions (unless, when)

A cedar file can contain a series of policy statements. Once a series of policy statements are executed, it will result in either "ALLOW" or "DENY". By default, everything not explicitly permitted results in "DENY", but this can be changed. See ["Setting Base Authorization"](https://hackmd.io/pZQrj_7HTMeBGP2PKMDljA#Setting-Base-Authorization). In instances where policies are conflicting, they will also return "DENY". 

Banyan makes use of decorators to extend the functionality of the Cedar Policy Language. A policy written in Banyan will follow the format in the example below.

```rust!
@name("Policy Statement 1 Name")
@message("This is the message returned when this policy fulfills it's action.")
@dependency("threatmodels.alerts")
@action("MFA")
permit(
    principal,
    action == 0xasldfakj,
    resource
) when {context.transaction.value.u256LessThan(u256("1234")) && threatmodels.alerts.time.u256LessThan(time.now()-time.hours(72))};
```
Contextual information is provided inside the json request.

#### Decorators
##### *@name*
This decorator is used to define and name a policy statement. This name will make an appearance in the Shield3 UI, messages sent to you regarding this policy, and can be used to reference the policy elsewhere.
```rust 
@name("Known phishing address")
```
##### *@message*
When the policy statement triggers a message, the user will receive this message. The message decorator was designed to be used as a way of warning against potentially risky situations.

```rust!
@message("Your transaction was blocked because the receiver of the transfer is a known phishing scammer. Please be sure to verify addresses before sending.")
```

##### *@action*
This is the action to carry out if the policy statement returns the relevant permission. The action can be defined as either Multi-Factor Authentication (MFA) or Notify. A DENY always results in block, however, ALLOW can result in either pass, notify, or MFA.

###### Block vs. Pass
Blocking means a transaction is not forwarded to the node service provider. If a transaction is blocked, a notification is sent to the transaction executor with the message defined in the *@message* decorator. If the transaction passes, then it is silently forwarded to the node service provider.



###### MFA
An MFA action is triggered when it's policy statement returns ALLOW. When MFA is triggered, the policy statement name, policy statement message, and transaction context will be sent to the transaction executor through their configured notifications, which can be found [here](url). 

The executor will then have the option to allow or deny the transaction. As shown previously, it's a good idea to set the message decorator as a warning, describing the risks coming with approving the transaction.
```rust
@action("MFA")
```

###### NOTIFY
When the notify action is triggered, the transaction will be broadcast as per usual, but notify the executor with the message provided from the message decorator.
```rust
@action("NOTIFY")
```
##### *@dependency*
```rust
@dependency("abcd-1234")
```
Any transaction context you'd like to reference can be found in your json request. Below is an example request, and a condition referencing it. In this case it returns a boolean to check if the network is mainnet ethereum. Any rich context you'd like to reference (information other than what is encoded in your transaction) must be defined as a dependency using the *@dependency* decorator. This rich context is then found in *entities.json*.

**request.json**
```json
{
  "principal": "Address::\"0xcfcdec1645234f521f29cb2bb0d57a539ba3bfae\"",
  "action": "Action::\"eoa\"",
  "resource": "Address::\"0x7c3250001bc0abeeef91f52e9054a9f951190132\"",
  "context": {
    "transaction": {
      "network": {
        "__entity": {
          "type": "Network",
          "id": "0x01"
        }
      },
      "data": "0x",
      "value": {
        "__expr": "u256(\"740048210\")"
      },
      "gasLimit": {
        "__expr": "u256(\"500000\")"
      }
    }
  }
}
```
**entities.json**
```json
[
  {
    "uid": {
      "type": "Address",
      "id": "0xd8a53b315823d8f8df8cb438c13ebe08af7c9ca9"
    },
    "attrs": {},
    "parents": []
  },
  {
    "uid": {
      "type": "Address",
      "id": "0x7a59293fe5fc36fdd762b4daeb07ba0873a3de44"
    },
    "attrs": {
      "groups": [
        {
          "__entity": {
            "type": "Group",
            "id": "1f033d2d-461a-4ce4-9026-5eb7efff5b4a"
          }
        }
      ]
    },
    "parents": []
  },
  {
    "uid": {
      "type": "Address",
      "id": "0xcfcdec1645234f521f29cb2bb0d57a539ba3bfae"
    },
    "attrs": {},
    "parents": []
  },
  {
    "uid": {
      "type": "Address",
      "id": "0x7c3250001bc0abeeef91f52e9054a9f951190132"
    },
    "attrs": {},
    "parents": []
  },
  {
    "uid": {
      "type": "Group",
      "id": "1f033d2d-461a-4ce4-9026-5eb7efff5b4a"
    },
    "attrs": {},
    "parents": []
  },
  {
    "uid": {
      "type": "Network",
      "id": "0x01"
    },
    "attrs": {
      "blockNumber": 18372931
    },
    "parents": []
  }
]

```

**policies.cedar**
```json
@name("Base Permit")
permit(
		principal,
		action,
		resource
);


@name("Sanctions")
@message("Block Sanctioned Addresses")
@action("Block")
@dependency("verified_addresses:1f033d2d-461a-4ce4-9026-5eb7efff5b4a")
forbid(
		principal,
		action,
		resource
) when {  resource has groups && resource.groups.contains(Group::"1f033d2d-461a-4ce4-9026-5eb7efff5b4a") };

```



### Recommended Policy Book

- Setting default authorization
- No approvals to EOAs
- No unlimited approvals
- Approve up to X $USD
- Block approval on list of token(s)
- Only have X concurrent approvals per token
- No transactions to addresses that are in a group with a scam/sanctionned address
- MFA on transactions with addresses that have been identified (victim or attacker) in a forta alert in the last x days (5?)
- Address Whitelist/Blacklist
- Chain Whitelist/Blacklist
- MFA to unknown contracts
- Block unverified contracts
- Only interact with addresses aged x+ blocks
- Only interact with addresses with address with x+ activity
- Only allow methods previously executed x+ times
- Block transactions to contracts with recent proxy implementation changes
- Block transactions to contracts with members recently added to it's group

#### Setting Default Authorization
If left unspecified, anything that is not explicitly allowed will automatically be denied. To make all unspecified requests allowed, simply add this to **policies.cedar**:

```rust
@name("Default Permit")
permit(
		principal,
		action,
		resource
);
```
#### No approvals to EOAs
```rust
@name("Block approvals to EOAs")
@message("This transaction was blocked because the address you're attempting to approve an EOA to spend your tokens")
forbid(
		principal,
		action,
		resource
) when {resource.method==
"Approve" && resource.contract.data=="0x"};
```

#### No unlimited approvals
```rust
@name("No unlimited approvals")
@message("Unlimited approvals are not allowed. Set an approval limit")
forbid(
		principal,
		action,
		resource
) when {resource.method==
"Approve" && context.transaction.approve_value.u256Equals(u256(2^256)) };
```
#### Approve up to X $USD
```rust!
@name("Approve up to X Dollars")
@message("The approval in this transaction exceeds the configured max amount in USD.")
forbid(
		principal,
		action,
		resource
) when {resource.method==
"Approve" && context.transaction.approve_value.USD.u256GreaterThan(u256("123")) };
```
#### Block approval on list of tokens
```rust!
@name("Block approval on list of tokens")
@message("The approval in this transaction exceeds the configured max amount in USD.")
forbid(
		principal,
		action,
		resource
) when {resource.method==
"Approve" && context.transaction.to.in(['0x123','0x456','0x789']) };
```
#### Max Concurrent Approvals

```rust
@name("Max Concurrent Approvals")
@message("This approval would cause you to exceed the maximum number of concurrent approvals allowed for this token.")
@dependency("count of approvals from executor on the to address")
forbid(
		principal,
		action,
		resource
) 
when {
    resource.method=="Approve" &&
    dependencyxyz.u256GreaterThanEqual("X") 
}
unless {resource.value.u256Equals('0')};
