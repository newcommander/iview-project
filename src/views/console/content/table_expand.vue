<style scoped>
	.expand-row{
		margin-bottom: 16px;
	}
</style>
<template>
	<div>
		<Row class="expand-row">
			<Col span="8">
				<span class="expand-key">Netmask: </span>
				<span class="expand-value">{{ row.netmask }}</span>
			</Col>
			<Col span="8">
				<span class="expand-key">Broadcast: </span>
				<span class="expand-value">{{ row.broadcast }}</span>
			</Col>
			<Col span="8">
				<span class="expand-key">Peer: </span>
				<span class="expand-value">{{ row.peer }}</span>
			</Col>
		</Row>
	</div>
</template>
<script>
	export default {
		props: { row: Object }
	};
</script>
