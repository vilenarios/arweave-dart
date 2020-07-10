import 'dart:convert';

import 'package:arweave/arweave.dart';
import 'package:test/test.dart';

import 'utils.dart';

const liveDataTxId = "bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U";

void main() {
  Arweave client;

  setUp(() {
    client = getArweaveClient();
  });

  test('create and sign data transaction', () async {
    final wallet = await client.wallets.generate();

    final transaction =
        await client.createTransaction(Transaction(data: 'test'), wallet);

    transaction.addTag("test-tag-1", "test-value-1");
    transaction.addTag("test-tag-2", "test-value-2");
    transaction.addTag("test-tag-3", "test-value-3");

    expect(transaction.data, equals('dGVzdA'));
    expect(transaction.lastTx, matches(r'/^[a-z0-9-_]{64}$/i'));
    expect(transaction.reward, matches(r'/^[0-9]+$/'));

    await client.transactions.sign(transaction, wallet);

    expect(transaction.signature, matches(r'/^[a-z0-9-_]{64}$/i'));
    expect(transaction.id, matches(digestRegex));

    expect(await client.transactions.verify(transaction), isTrue);

    transaction.setData('123', computeDataDetails: false);
    expect(await client.transactions.verify(transaction), isFalse);
  });

  test('create and sign AR transaction', () async {
    final wallet = await client.wallets.generate();

    final transaction = await client.createTransaction(
        Transaction(
          target: 'GRQ7swQO1AMyFgnuAPI7AvGQlW3lzuQuwlJbIpWV7xk',
          quantity: 'artoWInston',
        ),
        wallet);

    expect(transaction.quantity, equals('1500000000000'));
    expect(transaction.target,
        equals('GRQ7swQO1AMyFgnuAPI7AvGQlW3lzuQuwlJbIpWV7xk'));
  });

  test('get transaction status', () async {
    final status = await client.transactions.getStatus(liveDataTxId);
    expect(status.status, equals(200));
    expect(status.confirmed, isNotNull);
  });

  test('get transaction data', () async {
    final txRawData = await client.transactions.getData(liveDataTxId);
    expect(txRawData, contains("CjwhRE9DVFlQRSBodG1sPgo"));

    final txDecodedData = base64.decode(txRawData);
    expect(txDecodedData, contains([10, 60, 33, 68]));
  });

  test('search transactions', () async {
    final results =
        await client.transactions.search('Silo-Name', 'BmjRGIsemI77+eQb4zX8');
    expect(results, contains('Sgmyo7nUqPpVQWUfK72p5yIpd85QQbhGaWAF-I8L6yE'));
  });
}
